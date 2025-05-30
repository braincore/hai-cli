use assert_cmd::Command;
use predicates::str::contains;

fn default_cmd() -> Command {
    let mut cmd = Command::cargo_bin("hai").unwrap();
    cmd.current_dir(env!("CARGO_MANIFEST_DIR")); // Set to crate root
    cmd.arg("-u").arg("_").arg("bye");
    cmd
}

#[test]
fn test_account() {
    default_cmd()
        .arg("/account")
        .assert()
        .stdout(contains("You have not logged into an account."));
}

#[test]
fn test_exec() {
    default_cmd()
        .arg("/exec ls")
        .assert()
        .stdout(contains("Cargo.toml"));

    default_cmd()
        .arg("/e ls")
        .assert()
        .stdout(contains("Cargo.toml"));

    default_cmd()
        .arg("!!ls")
        .assert()
        .stdout(contains("Cargo.toml"));
}

#[test]
fn test_tool_mode() {
    default_cmd()
        .arg("!sh")
        .assert()
        .stdout(contains("Entering tool mode"));
}

#[test]
fn test_new() {
    default_cmd()
        .arg("/new")
        .assert()
        .stdout(contains("New conversation begun"));

    default_cmd()
        .arg("/n")
        .assert()
        .stdout(contains("New conversation begun"));
}
