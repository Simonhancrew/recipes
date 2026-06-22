use fordir::{collect_repos_from, parse_args, Options, ParsedArgs};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn parse_args_supports_flags_and_command() {
    let parsed = parse_args([
        OsString::from("--recursive"),
        OsString::from("--hidden"),
        OsString::from("--self"),
        OsString::from("git"),
        OsString::from("status"),
    ])
    .expect("parse should succeed");

    let ParsedArgs::Run { options, command } = parsed else {
        panic!("expected runnable command");
    };

    assert!(options.recursive);
    assert!(options.include_hidden);
    assert!(options.include_self);
    assert_eq!(command, vec![OsString::from("git"), OsString::from("status")]);
}

#[test]
fn parse_args_supports_help() {
    let parsed = parse_args([OsString::from("--help")]).expect("help should parse");
    assert!(matches!(parsed, ParsedArgs::Help));
}

#[test]
fn parse_args_rejects_unknown_option() {
    let error = match parse_args([OsString::from("--wat")]) {
        Ok(_) => panic!("unknown option should fail"),
        Err(error) => error,
    };
    assert!(error.contains("Unknown option: --wat"));
}

#[test]
fn collect_repos_non_recursive_skips_hidden() {
    let temp = TestDir::new("non-recursive");
    init_repo(&temp.path.join("visible-repo"));
    init_repo(&temp.path.join(".hidden-repo"));
    init_repo(&temp.path.join("parent").join("nested-repo"));

    let repos = collect_repos_from(&temp.path, Options::default()).expect("collect should work");
    assert_eq!(repos, vec![String::from("visible-repo")]);
}

#[test]
fn collect_repos_recursive_finds_nested_and_hidden_when_requested() {
    let temp = TestDir::new("recursive");
    init_repo(&temp.path.join("visible-repo"));
    init_repo(&temp.path.join(".hidden-repo"));
    init_repo(&temp.path.join("parent").join("nested-repo"));

    let repos = collect_repos_from(
        &temp.path,
        Options {
            recursive: true,
            include_hidden: true,
            include_self: false,
        },
    )
    .expect("collect should work");

    assert_eq!(
        repos,
        vec![
            String::from(".hidden-repo"),
            String::from("parent/nested-repo"),
            String::from("visible-repo"),
        ]
    );
}

#[test]
fn collect_repos_can_include_self() {
    let temp = TestDir::new("self");
    init_repo(&temp.path);

    let repos = collect_repos_from(
        &temp.path,
        Options {
            recursive: false,
            include_hidden: false,
            include_self: true,
        },
    )
    .expect("collect should work");

    assert_eq!(repos, vec![String::from(".")]);
}

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(name: &str) -> Self {
        let path = env::temp_dir().join(format!(
            "fordir-test-{}-{}-{}",
            std::process::id(),
            name,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&path).expect("temp dir should be created");
        Self { path }
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn init_repo(path: &Path) {
    fs::create_dir_all(path).expect("repo dir should be created");
    let status = Command::new("git")
        .arg("init")
        .arg(path)
        .status()
        .expect("git init should run");
    assert!(status.success(), "git init should succeed");
}
