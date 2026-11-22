// Every build of this package is the shuttle build of shioko.
fn main() {
    println!("cargo:rustc-cfg=shuttle");
}
