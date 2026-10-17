use std::env;
use std::path::PathBuf;

fn main() {
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86") {
        panic!("This project must be compiled for 32-bit x86.");
    }
    let libdir_path =
        dunce::canonicalize("src/dotnet_reflection").expect("cannot canonicalize path");
    let headers_path = libdir_path.join("dotnet_reflection.hpp");
    let headers_path_str = headers_path.to_str().expect("Path is not valid UTF-8");

    println!("cargo:rerun-if-changed={}", headers_path_str);
    println!(
        "cargo:rerun-if-changed={}",
        libdir_path.join("dotnet_reflection.cpp").display()
    );

    // --- .NET Framework SDK (cor.h, mscoree.h, etc.) ---
    let netfxsdk_dir = env::var("NETFXSDKDir").unwrap_or_else(|_| {
        panic!(
            "NETFXSDKDir not set.\n\
             Install the .NET Framework SDK (4.8) or run from a VS Developer Prompt."
        )
    });
    println!("{}", netfxsdk_dir);
    let netfx_include = PathBuf::from(&netfxsdk_dir).join("Include").join("um");

    let arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "x86" => "x86",
        "x86_64" => "x64",
        other => panic!("unsupported arch: {other}"),
    };
    let netfx_lib = PathBuf::from(&netfxsdk_dir)
        .join("Lib")
        .join("um")
        .join(arch);

    // --- Compile the C++ source ---
    cc::Build::new()
        .cpp(true)
        .std("c++20")
        .file(libdir_path.join("dotnet_reflection.cpp"))
        .include(&libdir_path)
        .include(&netfx_include)
        .compile("dotnet_reflection");

    // --- Link against corguids (ICorDebug GUIDs etc.) ---
    println!("cargo:rustc-link-search=native={}", netfx_lib.display());
    println!("cargo:rustc-link-lib=static=corguids");

    // --- Generate bindings ---
    let bindings = bindgen::Builder::default()
        .header(headers_path_str)
        .clang_arg("-std=c++20")
        // .clang_arg(format!("-I{}", netfx_include.display()))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs");
    bindings
        .write_to_file(out_path)
        .expect("Couldn't write bindings!");
}
