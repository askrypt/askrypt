use winresource::WindowsResource;

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os != "windows" {
        return;
    }
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut res = WindowsResource::new();
    res.set_icon(&format!("{manifest_dir}/static/logo-128.ico"));
    res.compile().expect("failed to build executable logo");
}
