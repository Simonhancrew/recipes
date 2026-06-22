use std::process::ExitCode;

fn main() -> ExitCode {
    match fordir::run() {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}
