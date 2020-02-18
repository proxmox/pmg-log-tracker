use std::fs::File;
use std::io::BufReader;
use std::process::Command;
mod utils;

#[test]
fn after_queue_start_end_time_string() {
    let output = Command::new("./target/debug/pmg-log-tracker")
        .arg("-vv")
        .arg("-s")
        .arg("2020-12-18 15:40:00")
        .arg("-e")
        .arg("2020-12-18 16:00:00")
        .arg("-i")
        .arg("tests/test_input_mixed")
        .output()
        .expect("failed to execute pmg-log-tracker");

    let expected_file = File::open("tests/test_output_after_queue")
        .expect("failed to open test_output");

    let expected_output = BufReader::new(&expected_file);
    let output_reader = BufReader::new(&output.stdout[..]);
    utils::compare_output(output_reader, expected_output);
}

#[test]
fn after_queue_start_end_timestamp() {
    let output = Command::new("./target/debug/pmg-log-tracker")
        .arg("-vv")
        .arg("-s")
        .arg("1608302400")
        .arg("-e")
        .arg("1608303600")
        .arg("-i")
        .arg("tests/test_input_mixed")
        .output()
        .expect("failed to execute pmg-log-tracker");

    let expected_file = File::open("tests/test_output_after_queue")
        .expect("failed to open test_output");

    let expected_output = BufReader::new(&expected_file);
    let output_reader = BufReader::new(&output.stdout[..]);
    utils::compare_output(output_reader, expected_output);
}

#[test]
fn after_queue_qid() {
    let output = Command::new("./target/debug/pmg-log-tracker")
        .arg("-vv")
        .arg("-s")
        .arg("1608302400")
        .arg("-e")
        .arg("1608303600")
        .arg("-i")
        .arg("tests/test_input_mixed")
        .arg("-q")
        .arg("0022C3801B5")
        .output()
        .expect("failed to execute pmg-log-tracker");

    let expected_file = File::open("tests/test_output_after_queue_qid")
        .expect("failed to open test_output");

    let expected_output = BufReader::new(&expected_file);
    let output_reader = BufReader::new(&output.stdout[..]);
    utils::compare_output(output_reader, expected_output);
}

#[test]
fn after_queue_host() {
    let output = Command::new("./target/debug/pmg-log-tracker")
        .arg("-vv")
        .arg("-s")
        .arg("1608302400")
        .arg("-e")
        .arg("1608303600")
        .arg("-i")
        .arg("tests/test_input_mixed")
        .arg("-h")
        .arg("localhost")
        .output()
        .expect("failed to execute pmg-log-tracker");

    let expected_file = File::open("tests/test_output_after_queue_host")
        .expect("failed to open test_output");

    let expected_output = BufReader::new(&expected_file);
    let output_reader = BufReader::new(&output.stdout[..]);
    utils::compare_output(output_reader, expected_output);
}

#[test]
fn after_queue_search_string() {
    let output = Command::new("./target/debug/pmg-log-tracker")
        .arg("-vv")
        .arg("-s")
        .arg("1608302400")
        .arg("-e")
        .arg("1608303600")
        .arg("-i")
        .arg("tests/test_input_mixed")
        .arg("-x")
        .arg("reject")
        .output()
        .expect("failed to execute pmg-log-tracker");

    let expected_file = File::open("tests/test_output_after_queue_search_string")
        .expect("failed to open test_output");

    let expected_output = BufReader::new(&expected_file);
    let output_reader = BufReader::new(&output.stdout[..]);
    utils::compare_output(output_reader, expected_output);
}
