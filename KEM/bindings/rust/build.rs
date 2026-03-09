use std::env;
use std::path::PathBuf;
use std::process::Command;

fn find_brew_prefix(package: &str) -> Option<PathBuf> {
    let output = Command::new("brew")
        .args(["--prefix", package])
        .output()
        .ok()?;
    if output.status.success() {
        let path = String::from_utf8(output.stdout).ok()?.trim().to_string();
        Some(PathBuf::from(path))
    } else {
        None
    }
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let kem_root = manifest_dir
        .parent() // bindings/
        .unwrap()
        .parent() // KEM/
        .unwrap()
        .to_path_buf();

    let include_dir = kem_root.join("include");
    let internal_dir = kem_root.join("src").join("internal");

    // Find OpenSSL
    let (openssl_include, openssl_lib) = if let Ok(info) = pkg_config::probe_library("openssl") {
        (
            info.include_paths.first().cloned().unwrap_or_default(),
            info.link_paths.first().cloned().unwrap_or_default(),
        )
    } else if cfg!(target_os = "macos") {
        let prefix =
            find_brew_prefix("openssl@3").expect("OpenSSL not found. Install with: brew install openssl@3");
        (prefix.join("include"), prefix.join("lib"))
    } else {
        panic!("OpenSSL not found. Install libssl-dev (Debian/Ubuntu) or openssl-devel (RHEL/Fedora).");
    };

    // Find GMP
    let (gmp_include, gmp_lib) = if let Ok(info) = pkg_config::probe_library("gmp") {
        (
            info.include_paths.first().cloned().unwrap_or_default(),
            info.link_paths.first().cloned().unwrap_or_default(),
        )
    } else if cfg!(target_os = "macos") {
        let prefix =
            find_brew_prefix("gmp").expect("GMP not found. Install with: brew install gmp");
        (prefix.join("include"), prefix.join("lib"))
    } else {
        panic!("GMP not found. Install libgmp-dev (Debian/Ubuntu) or gmp-devel (RHEL/Fedora).");
    };

    // Compile KAZ-KEM C sources
    cc::Build::new()
        .file(internal_dir.join("kem_secure.c"))
        .file(internal_dir.join("nist_wrapper.c"))
        .include(&include_dir)
        .include(&internal_dir)
        .include(&openssl_include)
        .include(&gmp_include)
        .warnings(false)
        .opt_level(2)
        .compile("kazkem");

    // Link dependencies
    println!("cargo:rustc-link-search=native={}", openssl_lib.display());
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-search=native={}", gmp_lib.display());
    println!("cargo:rustc-link-lib=gmp");

    // Re-run if sources change
    println!("cargo:rerun-if-changed={}", internal_dir.join("kem_secure.c").display());
    println!("cargo:rerun-if-changed={}", internal_dir.join("nist_wrapper.c").display());
    println!("cargo:rerun-if-changed={}", include_dir.join("kaz").join("kem.h").display());
}
