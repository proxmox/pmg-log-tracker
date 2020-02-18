use std::io::BufRead;

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
    for (old, new) in expected_lines.iter().zip(command_lines.iter())
    {
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
