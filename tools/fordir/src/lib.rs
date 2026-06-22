use std::collections::BTreeSet;
use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::fs::File;
use std::io::{self, IsTerminal, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

pub const USAGE: &str = "\
Usage: fordir [options] -- <command> [args...]
       fordir [options] <command> [args...]

Run a command in each git repository under the current directory.

Options:
  -r, --recursive  Search nested repositories recursively.
  -H, --hidden     Include hidden directories.
  -s, --self       Include the current directory if it is a git repository.
  -h, --help       Show this help message.

Examples:
  fordir git status -sb
  fordir git pull
  fordir --recursive -- git rev-parse --abbrev-ref HEAD
";

const REPO_PREFIX_COLOR: &str = "\x1b[1;36m";
const COLOR_RESET: &str = "\x1b[0m";

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq)]
pub struct Options {
    pub recursive: bool,
    pub include_hidden: bool,
    pub include_self: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ParsedArgs {
    Help,
    Run {
        options: Options,
        command: Vec<OsString>,
    },
}

struct Job {
    index: usize,
    repo: String,
}

struct JobResult {
    index: usize,
    repo: String,
    exit_code: i32,
    output: Vec<u8>,
}

pub fn run() -> Result<u8, String> {
    let parsed = parse_args(env::args_os().skip(1))?;
    run_from_parsed_args(parsed)
}

pub fn run_from_parsed_args(parsed: ParsedArgs) -> Result<u8, String> {
    let ParsedArgs::Run { options, command } = parsed else {
        return Ok(0);
    };

    let repos = collect_repos(options).map_err(|err| err.to_string())?;

    if repos.is_empty() {
        println!("No git repositories found.");
        return Ok(0);
    }

    let result_rx = run_command_in_repos(&repos, &command).map_err(|err| err.to_string())?;
    let repo_count = repos.len();
    let printer = thread::spawn(move || print_results(repo_count, result_rx));

    match printer.join() {
        Ok(result) => result,
        Err(_) => Err(String::from("printer thread panicked")),
    }
}

pub fn parse_args<I>(args: I) -> Result<ParsedArgs, String>
where
    I: IntoIterator<Item = OsString>,
{
    let args: Vec<OsString> = args.into_iter().collect();
    let mut options = Options::default();
    let mut index = 0usize;

    while index < args.len() {
        let current = &args[index];
        if current == "--" {
            index += 1;
            break;
        }

        let Some(flag) = current.to_str() else {
            break;
        };

        match flag {
            "-r" | "--recursive" => {
                options.recursive = true;
                index += 1;
            }
            "-H" | "--hidden" => {
                options.include_hidden = true;
                index += 1;
            }
            "-s" | "--self" => {
                options.include_self = true;
                index += 1;
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(ParsedArgs::Help);
            }
            _ if flag.starts_with('-') => {
                return Err(format!("Unknown option: {flag}\n{USAGE}"));
            }
            _ => break,
        }
    }

    if index == args.len() {
        return Err(USAGE.to_string());
    }

    let command = args[index..].to_vec();
    if command.is_empty() {
        return Err(USAGE.to_string());
    }

    Ok(ParsedArgs::Run { options, command })
}

pub fn collect_repos(options: Options) -> io::Result<Vec<String>> {
    let cwd = env::current_dir()?;
    collect_repos_from(&cwd, options)
}

pub fn collect_repos_from(root: &Path, options: Options) -> io::Result<Vec<String>> {
    let mut repos = BTreeSet::new();

    if options.include_self && is_repo_root(root)? {
        repos.insert(String::from("."));
    }

    if options.recursive {
        walk_recursive(root, Path::new("."), options.include_hidden, &mut repos)?;
    } else {
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }

            let relative = PathBuf::from(entry.file_name());
            if !options.include_hidden && is_hidden_path(&relative) {
                continue;
            }

            if is_repo_root(&entry.path())? {
                repos.insert(normalize_repo_path(&relative));
            }
        }
    }

    Ok(repos.into_iter().collect())
}

fn walk_recursive(
    root: &Path,
    relative: &Path,
    include_hidden: bool,
    repos: &mut BTreeSet<String>,
) -> io::Result<()> {
    for entry in fs::read_dir(root.join(relative))? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let name = entry.file_name();
        let child_relative = relative.join(&name);

        if file_type.is_dir() {
            if name == ".git" {
                let repo_relative = child_relative.parent().unwrap_or(Path::new("."));
                repos.insert(normalize_repo_path(repo_relative));
                continue;
            }

            if !include_hidden && is_hidden_path(&child_relative) {
                continue;
            }

            walk_recursive(root, &child_relative, include_hidden, repos)?;
            continue;
        }

        if (file_type.is_file() || file_type.is_symlink()) && name == ".git" {
            let repo_relative = child_relative.parent().unwrap_or(Path::new("."));
            repos.insert(normalize_repo_path(repo_relative));
            continue;
        }

        if !include_hidden && is_hidden_path(&child_relative) {
            continue;
        }
    }

    Ok(())
}

fn is_hidden_path(path: &Path) -> bool {
    path.components().any(|component| match component {
        Component::Normal(part) => part.to_string_lossy().starts_with('.'),
        _ => false,
    })
}

fn normalize_repo_path(path: &Path) -> String {
    let path = path.strip_prefix(".").unwrap_or(path);
    let value = path.to_string_lossy();
    if value.is_empty() {
        String::from(".")
    } else {
        value.into_owned()
    }
}

fn is_repo_root(dir: &Path) -> io::Result<bool> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "--show-toplevel"])
        .stderr(Stdio::null())
        .output()?;

    if !output.status.success() {
        return Ok(false);
    }

    let top = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if top.is_empty() {
        return Ok(false);
    }

    let dir_abs = fs::canonicalize(dir)?;
    let top_abs = fs::canonicalize(top)?;
    Ok(dir_abs == top_abs)
}

fn run_command_in_repos(
    repos: &[String],
    command: &[OsString],
) -> io::Result<mpsc::Receiver<JobResult>> {
    let worker_count = thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .max(1)
        .min(repos.len().max(1));
    let (job_tx, job_rx) = mpsc::channel::<Job>();
    let job_rx = Arc::new(Mutex::new(job_rx));
    let (result_tx, result_rx) = mpsc::channel::<JobResult>();
    let command = Arc::new(command.to_vec());

    let mut handles = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let job_rx = Arc::clone(&job_rx);
        let result_tx = result_tx.clone();
        let command = Arc::clone(&command);

        handles.push(thread::spawn(move || loop {
            let job = {
                let receiver = job_rx.lock().unwrap();
                receiver.recv()
            };

            let Ok(job) = job else {
                break;
            };

            let result = run_single_repo(job, command.as_slice());
            if result_tx.send(result).is_err() {
                break;
            }
        }));
    }
    drop(result_tx);

    for (index, repo) in repos.iter().enumerate() {
        job_tx
            .send(Job {
                index,
                repo: repo.clone(),
            })
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))?;
    }
    drop(job_tx);

    for handle in handles {
        thread::spawn(move || {
            let _ = handle.join();
        });
    }

    Ok(result_rx)
}

fn run_single_repo(job: Job, command: &[OsString]) -> JobResult {
    let output_path = temp_output_path(job.index);
    let output_file = File::options()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&output_path);

    let Ok(output_file) = output_file else {
        let err = output_file.err().unwrap();
        return JobResult {
            index: job.index,
            repo: job.repo.clone(),
            exit_code: 1,
            output: format!("Failed to prepare output capture in {}: {}", job.repo, err)
                .into_bytes(),
        };
    };

    let stdout_file = output_file.try_clone();
    let stderr_file = output_file.try_clone();
    let (Ok(stdout_file), Ok(stderr_file)) = (stdout_file, stderr_file) else {
        let _ = fs::remove_file(&output_path);
        return JobResult {
            index: job.index,
            repo: job.repo.clone(),
            exit_code: 1,
            output: format!("Failed to prepare output capture in {}", job.repo).into_bytes(),
        };
    };

    let mut process = Command::new(&command[0]);
    process.args(&command[1..]);
    process.current_dir(&job.repo);
    process.stdout(Stdio::from(stdout_file));
    process.stderr(Stdio::from(stderr_file));

    let status = process.status();
    drop(output_file);

    let mut output = fs::read(&output_path).unwrap_or_default();
    let _ = fs::remove_file(&output_path);

    match status {
        Ok(status) => JobResult {
            index: job.index,
            repo: job.repo,
            exit_code: status.code().unwrap_or(1),
            output,
        },
        Err(err) => {
            if !output.is_empty() && !output.ends_with(b"\n") {
                output.push(b'\n');
            }
            output.extend_from_slice(
                format!("Failed to run command in {}: {}", job.repo, err).as_bytes(),
            );
            JobResult {
                index: job.index,
                repo: job.repo,
                exit_code: 1,
                output,
            }
        }
    }
}

fn temp_output_path(index: usize) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);

    env::temp_dir().join(format!(
        "fordir-output-{}-{}-{}",
        std::process::id(),
        index,
        nanos + counter as u128
    ))
}

fn print_results(repo_count: usize, result_rx: mpsc::Receiver<JobResult>) -> Result<u8, String> {
    let stdout = io::stdout();
    let stderr = io::stderr();
    let use_color = stdout.is_terminal();
    let mut stdout = stdout.lock();
    let mut stderr = stderr.lock();
    let mut failed = 0usize;
    let mut expected_index = 0usize;
    let mut pending = HashMap::new();

    while expected_index < repo_count {
        let result = result_rx
            .recv()
            .map_err(|err| format!("result channel closed early: {err}"))?;
        pending.insert(result.index, result);

        while let Some(result) = pending.remove(&expected_index) {
            if use_color {
                writeln!(
                    stdout,
                    "{REPO_PREFIX_COLOR}==> {}{COLOR_RESET}",
                    result.repo
                )
                .map_err(|err| err.to_string())?;
            } else {
                writeln!(stdout, "==> {}", result.repo).map_err(|err| err.to_string())?;
            }
            stdout
                .write_all(&result.output)
                .and_then(|_| {
                    if result.output.is_empty() || result.output.ends_with(b"\n") {
                        Ok(())
                    } else {
                        stdout.write_all(b"\n")
                    }
                })
                .map_err(|err| err.to_string())?;

            if result.exit_code != 0 {
                stdout.flush().map_err(|err| err.to_string())?;
                failed += 1;
                writeln!(
                    stderr,
                    "Command failed in {} (exit {})",
                    result.repo, result.exit_code
                )
                .map_err(|err| err.to_string())?;
            }

            writeln!(stdout).map_err(|err| err.to_string())?;
            expected_index += 1;
        }
    }

    stdout.flush().map_err(|err| err.to_string())?;
    writeln!(
        stderr,
        "Processed {} repo(s); {} failed.",
        repo_count,
        failed
    )
    .map_err(|err| err.to_string())?;

    Ok(if failed == 0 { 0 } else { 1 })
}
