use std::fs::File;
use std::io::BufReader;
use std::process::Command;

mod utils;

#[test]
fn after_queue_time_change_string() {
    let output = Command::new("faketime")
        .arg("2021-01-01 23:59:59")
        .arg(utils::log_tracker_path())
        .arg("-vv")
        .arg("-s")
        .arg("2020-01-02 00:00:00")
        .arg("-e")
        .arg("2021-01-01 23:59:00")
        .arg("-i")
        .arg("tests/test_input_timechange")
        .output()
        .expect("failed to execute pmg-log-tracker");

    let expected_file =
        File::open("tests/test_output_timechange").expect("failed to open test_output");

    let expected_output = BufReader::new(&expected_file);
    let output_reader = BufReader::new(&output.stdout[..]);
    utils::compare_output(output_reader, expected_output);
}

