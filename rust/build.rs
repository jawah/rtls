use std::fs;

fn main() {
    // Extract dependency versions from Cargo.lock so we can expose them
    // at compile time via env!("RUSTLS_VERSION") and env!("AWS_LC_RS_VERSION").
    let lock = fs::read_to_string("Cargo.lock").expect("Cannot read Cargo.lock");

    let rustls_version = extract_version(&lock, "rustls");
    let aws_lc_rs_version = extract_version(&lock, "aws-lc-rs");

    println!("cargo:rustc-env=RUSTLS_VERSION={}", rustls_version);
    println!("cargo:rustc-env=AWS_LC_RS_VERSION={}", aws_lc_rs_version);
    println!("cargo:rerun-if-changed=Cargo.lock");
}

fn extract_version(lock_content: &str, package_name: &str) -> String {
    let target = format!(r#"name = "{}""#, package_name);
    let mut found = false;

    for line in lock_content.lines() {
        let line = line.trim();
        if line == target {
            found = true;
            continue;
        }
        if found && line.starts_with("version = \"") {
            return line
                .trim_start_matches("version = \"")
                .trim_end_matches('"')
                .to_string();
        }
    }

    "unknown".to_string()
}
