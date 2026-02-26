use winresource::WindowsResource;

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os != "windows" {
        return;
    }
    let mut res = WindowsResource::new();
    res.set_resource_file("res.rc");
    res.compile().expect("failed to build executable logo");
}
