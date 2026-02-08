use winresource::WindowsResource;

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os != "windows" {
        return;
    }
    let mut res = WindowsResource::new();
    let icon_path = "static/logo-128.ico";

    res.set_icon(icon_path);
    res.compile().expect("failed to build executable logo");
}
