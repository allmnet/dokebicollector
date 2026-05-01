fn main() {
    println!("cargo:rerun-if-changed=assets/dokebi.ico");

    #[cfg(windows)]
    {
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
            return;
        }

        let mut resource = winres::WindowsResource::new();
        resource.set_icon("assets/dokebi.ico");
        resource
            .compile()
            .expect("failed to compile Windows resources");
    }
}
