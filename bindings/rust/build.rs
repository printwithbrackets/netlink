// Links against the weft-net C library built by the top-level Makefile
// (`make` produces ../../build/libweft_net.a). Adjust WEFT_NET_LIB_DIR if
// you install the library elsewhere.
use std::env;
use std::path::PathBuf;

fn main() {
    let lib_dir = env::var("WEFT_NET_LIB_DIR").unwrap_or_else(|_| {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        PathBuf::from(manifest_dir)
            .join("../../build")
            .to_string_lossy()
            .into_owned()
    });

    println!("cargo:rustc-link-search=native={}", lib_dir);
    println!("cargo:rustc-link-lib=static=weft_net");
    println!("cargo:rustc-link-lib=dylib=crypto");
    println!("cargo:rustc-link-lib=dylib=pthread");
    println!("cargo:rerun-if-env-changed=WEFT_NET_LIB_DIR");
}
