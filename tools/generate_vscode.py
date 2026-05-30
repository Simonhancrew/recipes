#!/usr/bin/env python3
"""
Generate a VSCode workspace file (.code-workspace) for a Ninja-based project.

Usage:
    python3 misc/generate_vscode.py [-C <build-dir>] [--targets t1,t2,...]

What it does:
    1. Runs `ninja -t compdb` → compile_commands.json (for IntelliSense)
    2. Reads `build.ninja` to discover targets and executables
    3. Generates a <project>.code-workspace file with embedded:
       - Build tasks (shell tasks calling ninja)
       - Debug configurations (cppdbg launch configs)
       - Workspace settings (C++ IntelliSense, clangd)
       - Extension recommendations (cpptools, clangd)

    Double-click the .code-workspace file to open the project in VSCode.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Ninja file parser
# ---------------------------------------------------------------------------

class NinjaFile:
    """Minimal parser for .ninja build files.

    Extracts variables, rules, and build statements enough to identify
    what each target produces.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self.dir = os.path.dirname(os.path.abspath(path))

        # top-level variables (name → value, not expanded)
        self.vars: Dict[str, str] = {}
        # rule_name → {var: value, ...}  (the rule body)
        self.rules: Dict[str, Dict[str, str]] = {}
        # list of (outputs, rule_name, inputs, local_vars)
        self.builds: List[Tuple[List[str], str, List[str], Dict[str, str]]] = []

        self._parse()

    # ---- variable expansion ------------------------------------------
    _VAR_RE = re.compile(r'\$\{?(\w+)\}?')

    def expand(self, text: str, local_vars: Optional[Dict[str, str]] = None) -> str:
        """Expand ${var} references in *text* using global + local vars."""
        def _repl(m: re.Match) -> str:
            name = m.group(1)
            if local_vars and name in local_vars:
                # recursively expand (but guard against cycles)
                val = local_vars[name]
            elif name in self.vars:
                val = self.vars[name]
            else:
                return m.group(0)  # leave unknown
            # prevent infinite recursion on self-referential vars
            if val == text:
                return val
            return self.expand(val, local_vars)
        return self._VAR_RE.sub(_repl, text)

    # ---- parser -------------------------------------------------------
    _CONTINUATION = re.compile(r'(.*)\$\s*$')
    _ASSIGN = re.compile(r'^(\w+)\s*=\s*(.*)$')
    _RULE = re.compile(r'^rule\s+(\w+)$')
    _BUILD = re.compile(r'^build\s+(.*?):\s*(\w+)\s*(.*)$')

    def _parse(self) -> None:
        with open(self.path, encoding='utf-8') as f:
            lines = f.readlines()

        # join continuations
        accumulator: List[str] = []
        all_lines: List[str] = []
        for line in lines:
            raw = line.rstrip('\n')
            m = self._CONTINUATION.match(raw)
            if m:
                accumulator.append(m.group(1))
                continue
            if accumulator:
                # final line of a continuation group
                accumulator.append(raw)
                raw = ' '.join(accumulator)
                accumulator = []
            all_lines.append(raw)

        context: Optional[Tuple[str, str, Dict[str, str]]] = None
        # ("rule", name, dict) | ("build", rule_name, dict)

        for raw in all_lines:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue

            # indented line → belongs to current context
            if raw[0] in (' ', '\t') and context is not None:
                m = self._ASSIGN.match(line)
                if m:
                    ctx_type, ctx_name, ctx_vars = context
                    ctx_vars[m.group(1)] = m.group(2)
                continue

            context = None  # non-indented line ends context

            m = self._ASSIGN.match(line)
            if m:
                self.vars[m.group(1)] = m.group(2)
                continue

            m = self._RULE.match(line)
            if m:
                name = m.group(1)
                self.rules.setdefault(name, {})
                context = ('rule', name, self.rules[name])
                continue

            m = self._BUILD.match(line)
            if m:
                out_str = m.group(1)
                rule = m.group(2)
                inp_str = m.group(3)
                outputs = [o for o in out_str.split() if o.strip()]
                inputs = [i for i in inp_str.split() if i.strip()]
                local_vars: Dict[str, str] = {}
                self.builds.append((outputs, rule, inputs, local_vars))
                context = ('build', rule, local_vars)
                continue

    # ---- helpers ------------------------------------------------------
    @property
    def builddir(self) -> str:
        """Resolved build directory (where outputs land)."""
        d = self.vars.get('builddir', '.')
        d = self.expand(d)
        if not os.path.isabs(d):
            d = os.path.join(self.dir, d)
        return os.path.normpath(d)

    def targets_for_rule(self, rule_name: str) -> List[str]:
        """Return all output files for build statements using *rule_name*."""
        result: List[str] = []
        for outputs, rule, _inputs, _vars in self.builds:
            if rule == rule_name:
                result.extend(outputs)
        return result


# ---------------------------------------------------------------------------
# Executable detection heuristics
# ---------------------------------------------------------------------------

# Extensions that are almost certainly NOT standalone executables
_NON_EXEC_EXTS = {
    '.o', '.obj', '.a', '.lib', '.so', '.dylib', '.dll',
    '.pdb', '.ilk', '.exp',
}

# Rule name keywords that suggest a link step
_LINK_RULE_PATTERNS = [r'\blink\b', r'\bld\b', r'\bLINK\b', r'LINKER']


def _looks_like_link_rule(rule_name: str, cmd: str) -> bool:
    """Does *rule_name* / *cmd* look like it produces a linked binary?"""
    for pat in _LINK_RULE_PATTERNS:
        if re.search(pat, rule_name):
            return True
    # check command for linker drivers
    if re.search(r'\b(g\+\+|clang\+\+|ld|link\.exe|lld)\b', cmd, re.IGNORECASE):
        return True
    return False


def _looks_like_executable(output_path: str) -> bool:
    """Heuristic: does *output_path* look like an executable (not object/lib)?"""
    ext = os.path.splitext(output_path)[1].lower()
    if ext in _NON_EXEC_EXTS:
        return False
    # On Windows, .exe is executable; on Unix, no extension typically means exe
    return True


def detect_executables(ninja: NinjaFile) -> List[str]:
    """Return a list of targets (output file names) that are likely executables.

    Strategy:
      1. Find rules whose name or command looks like a link step.
      2. For those rules, find build-statement outputs.
      3. Filter outputs: drop object/library extensions.
    """
    candidates: List[str] = []

    # Build rule → expanded command map
    rule_commands: Dict[str, str] = {}
    for rule_name, body in ninja.rules.items():
        rule_commands[rule_name] = ninja.expand(body.get('command', ''))

    for outputs, rule_name, _inputs, _local in ninja.builds:
        cmd = rule_commands.get(rule_name, '')
        if _looks_like_link_rule(rule_name, cmd):
            for out in outputs:
                if _looks_like_executable(out):
                    candidates.append(out)

    # Deduplicate while preserving order
    seen: Set[str] = set()
    result: List[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            result.append(c)
    return result


# ---------------------------------------------------------------------------
# VSCode workspace generator
# ---------------------------------------------------------------------------

def generate_code_workspace(
    workspace_root: str,
    project_name: str,
    build_dir: str,
    build_output_dir: str,
    all_target: str,
    targets: List[str],
    executables: List[str],
    output_path: str,
) -> None:
    """Write a single <project>.code-workspace file with everything embedded.

    This is the VSCode equivalent of a "project file" — double-click to open
    the project with build tasks, debug configs, and IntelliSense ready.
    """

    # ---- path helpers --------------------------------------------------
    def _workspace_rel(dirpath: str) -> str:
        """Make *dirpath* workspace-relative for portability."""
        rel = os.path.relpath(dirpath, workspace_root)
        if rel == ".":
            return "."
        if not rel.startswith(".."):
            return "${workspaceFolder}/" + rel
        return dirpath  # outside workspace, fall back to absolute

    ninja_dir_ref = _workspace_rel(build_dir)

    # ---- tasks ---------------------------------------------------------
    tasks: List[dict] = []

    tasks.append({
        "label": "Ninja: Build All",
        "type": "shell",
        "command": "ninja",
        "args": ["-C", ninja_dir_ref, all_target],
        "group": {"kind": "build", "isDefault": True},
        "problemMatcher": ["$gcc"],
    })

    for t in targets:
        tasks.append({
            "label": f"Ninja: Build {t}",
            "type": "shell",
            "command": "ninja",
            "args": ["-C", ninja_dir_ref, t],
            "group": "build",
            "problemMatcher": ["$gcc"],
        })

    tasks.append({
        "label": "Ninja: Clean",
        "type": "shell",
        "command": "ninja",
        "args": ["-C", ninja_dir_ref, "-t", "clean"],
        "group": "build",
    })

    # ---- launch configs ------------------------------------------------
    configurations: List[dict] = []
    for exe in executables:
        exe_path = os.path.join(build_output_dir, exe)
        if os.path.isabs(exe_path):
            exe_path = os.path.relpath(exe_path, workspace_root)

        configurations.append({
            "name": f"Debug {exe}",
            "type": "cppdbg",
            "request": "launch",
            "program": "${workspaceFolder}/" + exe_path,
            "args": [],
            "stopAtEntry": False,
            "cwd": "${workspaceFolder}",
            "environment": [],
            "externalConsole": False,
            "MIMode": "gdb",
            "miDebuggerPath": "gdb",
            "preLaunchTask": f"Ninja: Build {exe}",
        })

    # ---- assemble workspace --------------------------------------------
    workspace = {
        "folders": [
            {
                "path": ".",
                "name": project_name,
            }
        ],
        "settings": {
            # C++ IntelliSense (Microsoft C/C++ extension)
            "C_Cpp.default.compileCommands":
                "${workspaceFolder}/compile_commands.json",
            "C_Cpp.default.includePath": ["${workspaceFolder}/**"],
            "C_Cpp.default.defines": [],
            # clangd
            "clangd.arguments": [
                "--compile-commands-dir=${workspaceFolder}",
                "--background-index",
            ],
            # File exclusions
            "files.exclude": {
                "**/.git": True,
                "**/.svn": True,
                "**/.hg": True,
            },
        },
        "tasks": {
            "version": "2.0.0",
            "tasks": tasks,
        },
        "launch": {
            "version": "0.2.0",
            "configurations": configurations,
        },
        "extensions": {
            "recommendations": [
                "ms-vscode.cpptools",
                "llvm-vs-code-extensions.vscode-clangd",
            ],
        },
    }

    # Remove empty sections to keep the file clean
    if not configurations:
        del workspace["launch"]
    if not tasks:
        del workspace["tasks"]

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(workspace, f, indent=2)
        f.write('\n')

    print(f"  ✓ {output_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a VSCode .code-workspace file for a Ninja-based project."
    )
    parser.add_argument(
        "-C", "--build-dir",
        default=None,
        help="Build directory containing build.ninja (default: search upwards).",
    )
    parser.add_argument(
        "-f", "--ninja-file",
        default="build.ninja",
        help="Name of the ninja build file (default: build.ninja).",
    )
    parser.add_argument(
        "--targets",
        default=None,
        help="Comma-separated list of targets to create debug configs for "
             "(default: auto-detect executables).",
    )
    parser.add_argument(
        "--all-target",
        default="all",
        help="Default build target (default: all).",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Path for the .code-workspace file (default: <project-root>/<dirname>.code-workspace).",
    )
    parser.add_argument(
        "--name",
        default=None,
        help="Project name in the workspace (default: directory name).",
    )
    parser.add_argument(
        "--no-compdb",
        action="store_true",
        help="Skip running 'ninja -t compdb'.",
    )
    args = parser.parse_args()

    # ---- locate build.ninja ------------------------------------------
    if args.build_dir:
        build_dir = os.path.abspath(args.build_dir)
    else:
        build_dir = os.getcwd()
        while build_dir != os.path.dirname(build_dir):
            if os.path.isfile(os.path.join(build_dir, args.ninja_file)):
                break
            build_dir = os.path.dirname(build_dir)
        else:
            build_dir = os.getcwd()

    ninja_path = os.path.join(build_dir, args.ninja_file)
    if not os.path.isfile(ninja_path):
        sys.exit(
            f"error: {args.ninja_file} not found in {build_dir}\n"
            f"       Use -C to specify the build directory."
        )

    print(f"Parsing {ninja_path} ...")
    ninja = NinjaFile(ninja_path)

    # ---- determine workspace root & project name ---------------------
    # Workspace root = project root (where .git lives, or cwd)
    d = os.getcwd()
    while d != os.path.dirname(d):
        if os.path.isdir(os.path.join(d, ".git")):
            break
        d = os.path.dirname(d)
    workspace_root = d
    project_name = args.name or os.path.basename(workspace_root)

    # ---- output path -------------------------------------------------
    if args.output:
        workspace_path = os.path.abspath(args.output)
    else:
        workspace_path = os.path.join(workspace_root, f"{project_name}.code-workspace")

    # ---- compile_commands.json ---------------------------------------
    if not args.no_compdb:
        print("Generating compile_commands.json ...")
        try:
            subprocess.run(
                ["ninja", "-C", build_dir, "-t", "compdb"],
                stdout=open(os.path.join(workspace_root, "compile_commands.json"), "w"),
                check=True,
                cwd=workspace_root,
            )
            print(f"  ✓ {os.path.join(workspace_root, 'compile_commands.json')}")
        except FileNotFoundError:
            print("  ⚠ ninja binary not found — skipping compile_commands.json")
        except subprocess.CalledProcessError as e:
            print(f"  ⚠ ninja -t compdb failed: {e}")

    # ---- detect executables ------------------------------------------
    if args.targets:
        executables = [t.strip() for t in args.targets.split(",") if t.strip()]
        print(f"\nUsing user-specified targets: {', '.join(executables)}")
    else:
        print("\nDetecting executable targets ...")
        executables = detect_executables(ninja)
        if executables:
            print(f"  Found: {', '.join(executables)}")
        else:
            print("  ⚠ No executable targets auto-detected. "
                  "Use --targets to specify manually.")

    targets_for_tasks = sorted(executables) if executables else []

    print(f"\nGenerating {os.path.basename(workspace_path)} ...")

    # ---- generate .code-workspace ------------------------------------
    generate_code_workspace(
        workspace_root=workspace_root,
        project_name=project_name,
        build_dir=build_dir,
        build_output_dir=ninja.builddir,
        all_target=args.all_target,
        targets=targets_for_tasks,
        executables=executables,
        output_path=workspace_path,
    )

    print(f"\nDone! Open it with:\n"
          f"  code {os.path.basename(workspace_path)}\n")


if __name__ == "__main__":
    main()
