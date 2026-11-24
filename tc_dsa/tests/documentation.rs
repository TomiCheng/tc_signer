//! Every public function, every method a type implements, and every helper of the digest
//! signers and the encodings documents its timing.

const METHODS: [&str; 16] = [
    "fmt",
    "init",
    "max_signature_size",
    "update",
    "generate_signature",
    "verify_signature",
    "reset",
    "max_encoding_size",
    "encode",
    "decode",
    "magnitude",
    "check",
    "der",
    "encoded_length",
    "value",
    "write_be",
];

fn checked(line: &str) -> bool {
    if line.starts_with("pub fn ") || line.starts_with("pub(crate) fn ") {
        return true;
    }
    line.strip_prefix("fn ")
        .and_then(|rest| rest.split(['(', '<']).next())
        .is_some_and(|name| METHODS.contains(&name))
}

fn missing_timing_docs(source: &str) -> (usize, Vec<String>) {
    let mut docs = String::new();
    let mut attribute_depth = 0_i32;
    let mut count = 0;
    let mut missing = Vec::new();
    let mut in_tests = false;
    for line in source.lines().map(str::trim) {
        if line == "mod tests {" {
            in_tests = true;
        }
        if let Some(comment) = line.strip_prefix("///") {
            // Lines join with a space, so that a classification may wrap.
            docs.push_str(comment.trim());
            docs.push(' ');
            continue;
        }
        if line.starts_with("#[") || attribute_depth > 0 {
            attribute_depth += line.chars().filter(|&c| c == '[').count() as i32;
            attribute_depth -= line.chars().filter(|&c| c == ']').count() as i32;
            continue;
        }
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        if !in_tests && checked(line) {
            count += 1;
            let docs = docs.to_ascii_lowercase();
            if docs.contains("constant time") == docs.contains("variable time") {
                missing.push(line.to_owned());
            }
        }
        docs.clear();
    }
    (count, missing)
}

/// The digest signers, the encodings and their errors. The `Dsa`, `DsaInit` and `DsaKCalculator`
/// traits make no timing promise, as `tc_signer`'s do not, and each k calculator states its own.
#[test]
fn every_public_method_and_helper_states_constant_or_variable_time() {
    for (name, source, minimum) in [
        (
            "digest_signer.rs",
            include_str!("../src/digest_signer.rs"),
            7,
        ),
        (
            "digest_signer_error.rs",
            include_str!("../src/digest_signer_error.rs"),
            1,
        ),
        ("encoding.rs", include_str!("../src/encoding.rs"), 2),
        (
            "gost3410_digest_signer.rs",
            include_str!("../src/gost3410_digest_signer.rs"),
            8,
        ),
        (
            "encoding/plain.rs",
            include_str!("../src/encoding/plain.rs"),
            3,
        ),
        (
            "encoding/standard.rs",
            include_str!("../src/encoding/standard.rs"),
            6,
        ),
        (
            "encoding_error.rs",
            include_str!("../src/encoding_error.rs"),
            1,
        ),
        (
            "traits/dsa_encoding.rs",
            include_str!("../src/traits/dsa_encoding.rs"),
            3,
        ),
    ] {
        let (count, missing) = missing_timing_docs(source);
        assert!(count >= minimum, "only {count} methods scanned in {name}");
        assert!(
            missing.is_empty(),
            "missing timing docs in {name}: {missing:?}"
        );
    }
}
