# fordir

Run one command across multiple Git repositories under the current directory.

`fordir` executes repository jobs in parallel, but prints each repository's output in order so terminal output does not get interleaved.

## Usage

```bash
fordir [options] -- <command> [args...]
fordir [options] <command> [args...]
```

### Options

- `-r`, `--recursive`: search nested repositories recursively
- `-H`, `--hidden`: include hidden directories
- `-s`, `--self`: include the current directory if it is a Git repository
- `-h`, `--help`: show help

## Examples

```bash
fordir git status -sb
fordir git pull --rebase
fordir --recursive -- git rev-parse --abbrev-ref HEAD
```

## Install

Build and install into `~/.local/bin` with Cargo:

```bash
cargo install --path . --root ~/.local --force
```

Or build manually and copy the binary:

```bash
cargo build --release
cp target/release/fordir ~/.local/bin/fordir
chmod +x ~/.local/bin/fordir
```

Make sure `~/.local/bin` is on your `PATH`.

## Development

Run tests:

```bash
cargo test
```
