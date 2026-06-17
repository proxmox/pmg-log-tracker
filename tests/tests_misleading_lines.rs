use std::fs::File;
use std::io::BufReader;
use std::process::Command;
mod utils;

// Some postfix lines look like they could be a QID, like 'warning: [..];' but
// aren't. Test that they don't produce any stray messages on stderr when multiple
// like this exist (meaning they would have been parsed as QIDs)
#[test]
fn misleading_lines_are_ignored() {
    let output = Command::new("faketime")
        .env("TZ", "Europe/Vienna")
        .arg("2020-12-31 23:59:59")
        .arg(utils::log_tracker_path())
        .arg("-vv")
        .arg("-s")
        .arg("2020-12-18 15:00:00")
        .arg("-e")
        .arg("2026-06-16 15:40:00")
        .arg("-i")
        .arg("tests/test_input_misleading_lines")
        .output()
        .expect("failed to execute pmg-log-tracker");

    assert_eq!(String::from_utf8_lossy(&output.stderr), "".to_string());

    assert!(
        output.status.success(),
        "pmg-log-tracker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let expected_file =
        File::open("tests/test_output_misleading_lines").expect("failed to open test_output");

    let expected_output = BufReader::new(&expected_file);
    let output_reader = BufReader::new(&output.stdout[..]);
    utils::compare_output(output_reader, expected_output);
}
