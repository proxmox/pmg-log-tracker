use std::io::BufRead;

use std::env;
use std::path::PathBuf;

fn get_target_dir() -> PathBuf {
    let bin = env::current_exe().expect("exe path");
    let mut target_dir = PathBuf::from(bin.parent().expect("bin parent"));
    target_dir.pop();
    target_dir
}

pub fn log_tracker_path() -> String {
    let mut target_dir = get_target_dir();
    target_dir.push("pmg-log-tracker");
    target_dir.to_str().unwrap().to_string()
}

pub fn compare_output<R: BufRead, R2: BufRead>(command: R, expected: R2) {
    let expected_lines: Vec<String> = expected.lines().map(|l| l.unwrap()).collect();
    let command_lines: Vec<String> = command.lines().map(|l| l.unwrap()).collect();
    assert_eq!(
        expected_lines.len(),
        command_lines.len(),
        "expected: {}, command: {}",
        expected_lines.len(),
        command_lines.len()
    );
    for (old, new) in expected_lines.iter().zip(command_lines.iter()) {
        if new.starts_with("# ") && old.starts_with("# ") {
            continue;
        } else if new.starts_with("# ") {
            assert!(
                false,
                "comment line found in command output, but not in expected output"
            );
        } else if old.starts_with("# ") {
            assert!(
                false,
                "comment line found in expected output, but not in command output"
            );
        }

        assert_eq!(new, old);
    }
}
