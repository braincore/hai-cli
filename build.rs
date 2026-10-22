//! Build script.
//!
//! On macOS this compiles `src/macos/secure_enclave.swift` into a static
//! library that provides Secure Enclave (Touch ID) protection for asset
//! encryption passwords. If the Swift toolchain is unavailable, the build
//! continues without it and hai falls back to the OS keyring at runtime.
//! Set `HAI_REQUIRE_SE=1` to turn that fallback into a hard error (used by
//! release builds).

use std::env;
use std::path::PathBuf;
use std::process::Command;

const SWIFT_SRC: &str = "src/macos/secure_enclave.swift";

fn main() {
    println!("cargo::rustc-check-cfg=cfg(hai_se)");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={SWIFT_SRC}");
    println!("cargo:rerun-if-env-changed=HAI_REQUIRE_SE");
    println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    let require = env::var("HAI_REQUIRE_SE")
        .map(|v| v == "1")
        .unwrap_or(false);
    match build_swift() {
        Ok(()) => println!("cargo:rustc-cfg=hai_se"),
        Err(e) if require => panic!("failed to build Secure Enclave support: {e}"),
        Err(e) => println!("cargo:warning=Secure Enclave (Touch ID) support disabled: {e}"),
    }
}

fn run(cmd: &mut Command) -> Result<String, String> {
    let out = cmd
        .output()
        .map_err(|e| format!("failed to run {:?}: {e}", cmd.get_program()))?;
    if !out.status.success() {
        return Err(format!(
            "{:?} failed: {}",
            cmd.get_program(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn build_swift() -> Result<(), String> {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        other => return Err(format!("unsupported arch {other}")),
    };
    // CryptoKit's SecureEnclave API requires macOS 10.15.
    let min_os = env::var("MACOSX_DEPLOYMENT_TARGET")
        .unwrap_or_else(|_| if arch == "arm64" { "11.0" } else { "10.15" }.to_string());
    let swift_target = format!("{arch}-apple-macosx{min_os}");

    let sdk = run(Command::new("xcrun").args(["--sdk", "macosx", "--show-sdk-path"]))?;
    let swiftc = run(Command::new("xcrun").args(["--sdk", "macosx", "--find", "swiftc"]))?;

    let lib = out_dir.join("libhaise.a");
    run(Command::new(&swiftc).args([
        "-parse-as-library",
        "-static",
        "-emit-library",
        "-O",
        "-whole-module-optimization",
        "-swift-version",
        "5",
        "-module-name",
        "haise",
        "-target",
        &swift_target,
        "-sdk",
        &sdk,
        "-module-cache-path",
        out_dir.join("swift-module-cache").to_str().unwrap(),
        "-o",
        lib.to_str().unwrap(),
        SWIFT_SRC,
    ]))?;

    // Locate Swift runtime + compatibility libraries for the linker. The
    // static library's objects carry autolink directives for them.
    let info = run(Command::new(&swiftc).args(["-target", &swift_target, "-print-target-info"]))?;
    let info: serde_json::Value =
        serde_json::from_str(&info).map_err(|e| format!("bad target info: {e}"))?;
    if let Some(paths) = info["paths"]["runtimeLibraryPaths"].as_array() {
        for p in paths.iter().filter_map(|p| p.as_str()) {
            println!("cargo:rustc-link-search=native={p}");
        }
    }
    println!("cargo:rustc-link-search=native={sdk}/usr/lib/swift");
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=haise");
    for fw in ["Foundation", "CryptoKit", "LocalAuthentication", "Security"] {
        println!("cargo:rustc-link-lib=framework={fw}");
    }
    // The Swift runtime ships with the OS (macOS 10.14.4+).
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    Ok(())
}
