extern crate bindgen;
extern crate cmake;

use std::env;
use std::error::Error;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    // TODO: Env var for setting `-DARCH=native`.
    let mut config = cmake::Config::new("randomx");
    // CMake 4 no longer accepts RandomX's original pre-3.5 policy version.
    config
        .define("CMAKE_POLICY_VERSION_MINIMUM", "3.5")
        .build_target("randomx");
    let profile = config.get_profile().to_owned();
    let dst = config.build();

    // Visual Studio and other multi-config generators append the profile.
    println!(
        "cargo:rustc-link-search=native={}",
        dst.join("build").join(profile).display()
    );
    println!("cargo:rustc-link-search=native={}/build", dst.display());
    println!("cargo:rustc-link-lib=static=randomx");

    // CMake uses the platform's default C++ compiler. Match its runtime
    // library instead of hard-coding a library name that Cargo prefixes with
    // `lib` a second time.
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_env != "msvc" {
        let cxx_runtime = match target_os.as_str() {
            "macos" | "ios" | "freebsd" => "c++",
            _ => "stdc++",
        };
        println!("cargo:rustc-link-lib=dylib={cxx_runtime}");
    }

    let bindings = bindgen::Builder::default()
        .header("randomx/src/randomx.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .map_err(|_| std::io::Error::other("bindgen failed to generate RandomX bindings"))?;

    let out_path = PathBuf::from(env::var("OUT_DIR")?);
    bindings.write_to_file(out_path.join("bindings.rs"))?;
    Ok(())
}
