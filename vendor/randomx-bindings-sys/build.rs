extern crate bindgen;
extern crate cmake;

use std::env;
use std::path::PathBuf;

fn main() {
    // TODO: Env var for setting `-DARCH=native`.
    let dst = cmake::Config::new("randomx")
        .build_target("randomx")
        .build();

    println!("cargo:rustc-link-search=native={}/build", dst.display());
    println!("cargo:rustc-link-lib=static=randomx");

    // CMake uses the platform's default C++ compiler. Match its runtime
    // library instead of hard-coding a library name that Cargo prefixes with
    // `lib` a second time.
    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("target OS is set by Cargo");
    let cxx_runtime = match target_os.as_str() {
        "macos" | "ios" | "freebsd" => "c++",
        _ => "stdc++",
    };
    println!("cargo:rustc-link-lib=dylib={cxx_runtime}");

    let bindings = bindgen::Builder::default()
        .header("randomx/src/randomx.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Unable to write bindings");
}
