use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let sign_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("..")
        .join("..")
        .canonicalize()
        .expect("Failed to resolve SIGN root directory");

    let include_dir = sign_root.join("include");
    let internal_dir = sign_root.join("src").join("internal");

    // Find OpenSSL
    let (openssl_include, openssl_lib) = find_openssl();

    // Compile all C source files
    let c_files = [
        "sign.c",
        "nist_wrapper.c",
        "kdf.c",
        "security.c",
        "sha3.c",
        "detached.c",
        "der.c",
        "x509.c",
        "p12.c",
    ];

    let mut build = cc::Build::new();
    build
        .include(&include_dir)
        .include(&internal_dir)
        .include(&openssl_include)
        .flag("-std=c11")
        .flag("-O2");

    for file in &c_files {
        build.file(internal_dir.join(file));
    }

    build.compile("kazsign");

    // Link OpenSSL
    println!("cargo:rustc-link-search=native={}", openssl_lib.display());
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");

    // Link GMP
    let gmp_lib = find_gmp_lib();
    println!("cargo:rustc-link-search=native={}", gmp_lib.display());
    println!("cargo:rustc-link-lib=gmp");

    // Rerun if sources change
    println!("cargo:rerun-if-changed={}", internal_dir.display());
    println!("cargo:rerun-if-changed={}", include_dir.display());
}

fn find_openssl() -> (PathBuf, PathBuf) {
    // Try pkg-config first
    if let Ok(lib) = pkg_config::Config::new()
        .atleast_version("3.0")
        .probe("openssl")
    {
        let inc = lib
            .include_paths
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("/usr/include"));
        let lib_dir = lib
            .link_paths
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("/usr/lib"));
        return (inc, lib_dir);
    }

    // macOS: try brew --prefix openssl@3
    if cfg!(target_os = "macos") {
        if let Ok(output) = Command::new("brew")
            .args(["--prefix", "openssl@3"])
            .output()
        {
            if output.status.success() {
                let prefix = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let prefix = PathBuf::from(prefix);
                return (prefix.join("include"), prefix.join("lib"));
            }
        }
    }

    // Fallback
    (PathBuf::from("/usr/include"), PathBuf::from("/usr/lib"))
}

fn find_gmp_lib() -> PathBuf {
    // Try pkg-config
    if let Ok(lib) = pkg_config::probe_library("gmp") {
        if let Some(p) = lib.link_paths.first() {
            return p.clone();
        }
    }

    // macOS: try brew --prefix gmp
    if cfg!(target_os = "macos") {
        if let Ok(output) = Command::new("brew").args(["--prefix", "gmp"]).output() {
            if output.status.success() {
                let prefix = String::from_utf8_lossy(&output.stdout).trim().to_string();
                return PathBuf::from(prefix).join("lib");
            }
        }
    }

    PathBuf::from("/usr/lib")
}
