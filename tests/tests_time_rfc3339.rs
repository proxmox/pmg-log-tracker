use std::fs::File;
use std::io::BufReader;
use std::process::Command;

mod utils;

#[test]
fn after_queue_time_rfc3339_mixed() {
    let output = Command::new("faketime")
        .env("TZ", "Europe/Vienna")
        .arg("2023-06-28 23:59:59")
        .arg(utils::log_tracker_path())
        .arg("-vv")
        .arg("-s")
        .arg("2023-06-23 00:00:00")
        .arg("-e")
        .arg("2023-06-23 23:59:00")
        .arg("-i")
        .arg("tests/test_input_time_rfc3339_mixed")
        .output()
        .expect("failed to execute pmg-log-tracker");

    let expected_file =
        File::open("tests/test_output_time_rfc3339_mixed").expect("failed to open test_output");

    let expected_output = BufReader::new(&expected_file);
    let output_reader = BufReader::new(&output.stdout[..]);
    utils::compare_output(output_reader, expected_output);
}
