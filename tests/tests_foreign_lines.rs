use std::fs::File;
use std::io::BufReader;
use std::process::Command;
mod utils;

// Anything can log under the syslog identifiers the parser matches on, like a custom check
// script whose output ends up in the journal under the pmg-smtp-filter identifier. Lines that
// do not continue with ": " after a token that parses as a queue ID must neither panic the
// parser nor show up attached to real entries.
#[test]
fn foreign_lines_are_ignored() {
    let output = Command::new("faketime")
        .env("TZ", "Europe/Vienna")
        .arg("2020-12-31 23:59:59")
        .arg(utils::log_tracker_path())
        .arg("-vv")
        .arg("-s")
        .arg("2020-12-18 15:00:00")
        .arg("-e")
        .arg("2020-12-18 15:40:00")
        .arg("-i")
        .arg("tests/test_input_foreign_lines")
        .output()
        .expect("failed to execute pmg-log-tracker");

    assert!(
        output.status.success(),
        "pmg-log-tracker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let expected_file =
        File::open("tests/test_output_foreign_lines").expect("failed to open test_output");

    let expected_output = BufReader::new(&expected_file);
    let output_reader = BufReader::new(&output.stdout[..]);
    utils::compare_output(output_reader, expected_output);
}
