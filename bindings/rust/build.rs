// Links against the netlink C library built by the top-level Makefile
// (`make` produces ../../build/libnetlink.a). Adjust NETLINK_LIB_DIR if
// you install the library elsewhere.
use std::env;
use std::path::PathBuf;

fn main() {
    let lib_dir = env::var("NETLINK_LIB_DIR").unwrap_or_else(|_| {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        PathBuf::from(manifest_dir)
            .join("../../build")
            .to_string_lossy()
            .into_owned()
    });

    println!("cargo:rustc-link-search=native={}", lib_dir);
    println!("cargo:rustc-link-lib=static=netlink");
    println!("cargo:rustc-link-lib=dylib=crypto");
    println!("cargo:rustc-link-lib=dylib=pthread");
    println!("cargo:rerun-if-env-changed=NETLINK_LIB_DIR");
}
