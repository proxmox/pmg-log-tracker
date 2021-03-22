use std::fs::File;
use std::io::BufReader;
use std::process::Command;
mod utils;

#[test]
fn before_queue_start_end_time_string() {
    let output = Command::new("faketime")
        .arg("2020-12-31 23:59:59")
        .arg(utils::log_tracker_path())
        .arg("-vv")
        .arg("-s")
        .arg("2020-12-18 15:00:00")
        .arg("-e")
        .arg("2020-12-18 15:40:00")
        .arg("-i")
        .arg("tests/test_input_mixed")
        .output()
        .expect("failed to execute pmg-log-tracker");

    let expected_file =
        File::open("tests/test_output_before_queue").expect("failed to open test_output");

    let expected_output = BufReader::new(&expected_file);
    let output_reader = BufReader::new(&output.stdout[..]);
    utils::compare_output(output_reader, expected_output);
}

#[test]
fn before_queue_start_end_timestamp() {
    let output = Command::new("faketime")
        .arg("2020-12-31 23:59:59")
        .arg(utils::log_tracker_path())
        .arg("-vv")
        .arg("-s")
        .arg("1608300000")
        .arg("-e")
        .arg("1608302400")
        .arg("-i")
        .arg("tests/test_input_mixed")
        .output()
        .expect("failed to execute pmg-log-tracker");

    let expected_file =
        File::open("tests/test_output_before_queue").expect("failed to open test_output");

    let expected_output = BufReader::new(&expected_file);
    let output_reader = BufReader::new(&output.stdout[..]);
    utils::compare_output(output_reader, expected_output);
}

#[test]
fn before_queue_qid() {
    let output = Command::new("faketime")
        .arg("2020-12-31 23:59:59")
        .arg(utils::log_tracker_path())
        .arg("-vv")
        .arg("-s")
        .arg("1608300000")
        .arg("-e")
        .arg("1608302400")
        .arg("-i")
        .arg("tests/test_input_mixed")
        .arg("-q")
        .arg("1C6B541C5D")
        .output()
        .expect("failed to execute pmg-log-tracker");

    let expected_file =
        File::open("tests/test_output_before_queue_qid").expect("failed to open test_output");

    let expected_output = BufReader::new(&expected_file);
    let output_reader = BufReader::new(&output.stdout[..]);
    utils::compare_output(output_reader, expected_output);
}

#[test]
fn before_queue_host() {
    let output = Command::new("faketime")
        .arg("2020-12-31 23:59:59")
        .arg(utils::log_tracker_path())
        .arg("-vv")
        .arg("-s")
        .arg("1608300000")
        .arg("-e")
        .arg("1608302400")
        .arg("-i")
        .arg("tests/test_input_mixed")
        .arg("-h")
        .arg("localhost")
        .output()
        .expect("failed to execute pmg-log-tracker");

    let expected_file =
        File::open("tests/test_output_before_queue_host").expect("failed to open test_output");

    let expected_output = BufReader::new(&expected_file);
    let output_reader = BufReader::new(&output.stdout[..]);
    utils::compare_output(output_reader, expected_output);
}

#[test]
fn before_queue_search_string() {
    let output = Command::new("faketime")
        .arg("2020-12-31 23:59:59")
        .arg(utils::log_tracker_path())
        .arg("-vv")
        .arg("-s")
        .arg("1608300000")
        .arg("-e")
        .arg("1608302400")
        .arg("-i")
        .arg("tests/test_input_mixed")
        .arg("-x")
        .arg("reject")
        .output()
        .expect("failed to execute pmg-log-tracker");

    let expected_file = File::open("tests/test_output_before_queue_search_string")
        .expect("failed to open test_output");

    let expected_output = BufReader::new(&expected_file);
    let output_reader = BufReader::new(&output.stdout[..]);
    utils::compare_output(output_reader, expected_output);
}

#[test]
fn before_queue_search_string_case_insensitive() {
    let output = Command::new("faketime")
        .arg("2020-12-31 23:59:59")
        .arg(utils::log_tracker_path())
        .arg("-vv")
        .arg("-s")
        .arg("1608300000")
        .arg("-e")
        .arg("1608302400")
        .arg("-i")
        .arg("tests/test_input_mixed")
        .arg("-x")
        .arg("reJECT")
        .output()
        .expect("failed to execute pmg-log-tracker");

    let expected_file = File::open("tests/test_output_before_queue_search_string")
        .expect("failed to open test_output");

    let expected_output = BufReader::new(&expected_file);
    let output_reader = BufReader::new(&output.stdout[..]);
    utils::compare_output(output_reader, expected_output);
}

#[test]
fn before_queue_exclude_greylist_ndr() {
    let output = Command::new("faketime")
        .arg("2020-12-31 23:59:59")
        .arg(utils::log_tracker_path())
        .arg("-vv")
        .arg("-s")
        .arg("1608300000")
        .arg("-e")
        .arg("1608302400")
        .arg("-i")
        .arg("tests/test_input_mixed")
        .arg("-g")
        .arg("-n")
        .output()
        .expect("failed to execute pmg-log-tracker");

    let expected_file =
        File::open("tests/test_output_before_queue").expect("failed to open test_output");

    let expected_output = BufReader::new(&expected_file);
    let output_reader = BufReader::new(&output.stdout[..]);
    utils::compare_output(output_reader, expected_output);
}

#[test]
fn before_queue_to() {
    let output = Command::new("faketime")
        .arg("2020-12-31 23:59:59")
        .arg(utils::log_tracker_path())
        .arg("-vv")
        .arg("-s")
        .arg("1608300000")
        .arg("-e")
        .arg("1608302400")
        .arg("-i")
        .arg("tests/test_input_mixed")
        .arg("-t")
        .arg("pmgtes2")
        .output()
        .expect("failed to execute pmg-log-tracker");

    let expected_file =
        File::open("tests/test_output_before_queue_to").expect("failed to open test_output");

    let expected_output = BufReader::new(&expected_file);
    let output_reader = BufReader::new(&output.stdout[..]);
    utils::compare_output(output_reader, expected_output);
}

#[test]
fn before_queue_mixed_downstream() {
    let output = Command::new("faketime")
        .arg("2020-12-31 23:59:59")
        .arg(utils::log_tracker_path())
        .arg("-v")
        .arg("-s")
        .arg("1608303600")
        .arg("-e")
        .arg("1608304200")
        .arg("-i")
        .arg("tests/test_input_mixed")
        .output()
        .expect("failed to execute pmg-log-tracker");

    let expected_file = File::open("tests/test_output_before_queue_mixed_downstream")
        .expect("failed to open test_output");

    let expected_output = BufReader::new(&expected_file);
    let output_reader = BufReader::new(&output.stdout[..]);
    utils::compare_output(output_reader, expected_output);
}

#[test]
fn before_queue_from_to() {
    let output = Command::new("faketime")
        .arg("2020-12-31 23:59:59")
        .arg(utils::log_tracker_path())
        .arg("-vv")
        .arg("-s")
        .arg("1608300000")
        .arg("-e")
        .arg("1608302400")
        .arg("-i")
        .arg("tests/test_input_mixed")
        .arg("-f")
        .arg("mailtestsender3")
        .arg("-t")
        .arg("pmgtest")
        .output()
        .expect("failed to execute pmg-log-tracker");

    let expected_file =
        File::open("tests/test_output_before_queue_from_to").expect("failed to open test_output");

    let expected_output = BufReader::new(&expected_file);
    let output_reader = BufReader::new(&output.stdout[..]);
    utils::compare_output(output_reader, expected_output);
}

#[test]
fn before_queue_mixed_accept_block_quarantine() {
    let output = Command::new("faketime")
        .arg("2020-12-31 23:59:59")
        .arg(utils::log_tracker_path())
        .arg("-vv")
        .arg("-s")
        .arg("1588254000")
        .arg("-e")
        .arg("1588255200")
        .arg("-i")
        .arg("tests/test_input_mixed_accept_block_quarantine")
        .arg("-n")
        .output()
        .expect("failed to execute pmg-log-tracker");

    let expected_file = File::open("tests/test_output_before_queue_mixed_accept_block_quarantine")
        .expect("failed to open test_output");

    let expected_output = BufReader::new(&expected_file);
    let output_reader = BufReader::new(&output.stdout[..]);
    utils::compare_output(output_reader, expected_output);
}

#[test]
fn before_queue_to_search_string() {
    let output = Command::new("faketime")
        .arg("2020-12-31 23:59:59")
        .arg(utils::log_tracker_path())
        .arg("-vv")
        .arg("-s")
        .arg("1589810100")
        .arg("-e")
        .arg("1589812000")
        .arg("-i")
        .arg("tests/test_input_before_queue_to_search_string")
        .arg("-t")
        .arg("ferdl@example.proxmox.com")
        .arg("-x")
        .arg("ferdl@example.proxmox.com")
        .output()
        .expect("failed to execute pmg-log-tracker");

    let expected_file = File::open("tests/test_output_before_queue_to_search_string")
        .expect("failed to open test_output");

    let expected_output = BufReader::new(&expected_file);
    let output_reader = BufReader::new(&output.stdout[..]);
    utils::compare_output(output_reader, expected_output);
}

#[test]
fn before_queue_syntax_reject() {
    let output = Command::new("faketime")
        .arg("2020-12-31 23:59:59")
        .arg(utils::log_tracker_path())
        .arg("-vv")
        .arg("-s")
        .arg("2020-08-27 14:00:00")
        .arg("-e")
        .arg("2020-08-27 14:05:00")
        .arg("-i")
        .arg("tests/test_input_before_queue_syntax_reject")
        .output()
        .expect("failed to execute pmg-log-tracker");

    let expected_file = File::open("tests/test_output_before_queue_syntax_reject")
        .expect("failed to open test_output");

    let expected_output = BufReader::new(&expected_file);
    let output_reader = BufReader::new(&output.stdout[..]);
    utils::compare_output(output_reader, expected_output);
}
