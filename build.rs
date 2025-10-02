fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let mut res = winres::WindowsResource::new();
    res.set_icon("good-bye-mshta.ico");
    res.compile().expect("failed to embed icon");
}
