fn main() {
    println!("cargo:rustc-check-cfg=cfg(kindasafe_init_asan)");
    let sanitizers = std::env::var("CARGO_CFG_SANITIZE").unwrap_or_default();
    if sanitizers
        .split(',')
        .any(|sanitizer| sanitizer == "address")
    {
        println!("cargo:rustc-cfg=kindasafe_init_asan");
    }
}
