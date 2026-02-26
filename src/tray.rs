use std::sync::mpsc::{self, Receiver};
use tray_item::{IconSource, TrayItem};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayEvent {
    Open,
    Quit,
}

pub struct AppTray {
    _tray_icon: TrayItem,
    pub receiver: Receiver<TrayEvent>,
}

impl AppTray {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let (tx, rx) = mpsc::channel();

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let icon = {
            let img = image::load_from_memory(include_bytes!("../static/logo-32.png"))
                .expect("Failed to load tray icon");
            let rgba = img.to_rgba8();
            let (width, height) = (rgba.width(), rgba.height());
            // ksni expects ARGB32, network byte order (big-endian): [A, R, G, B]
            let data = rgba
                .pixels()
                .flat_map(|p| {
                    let [r, g, b, a] = p.0;
                    [a, r, g, b]
                })
                .collect();
            IconSource::Data {
                data,
                width: width as i32,
                height: height as i32,
            }
        };

        #[cfg(target_os = "windows")]
        let icon = IconSource::Resource("main-exe-icon");

        let mut tray = TrayItem::new("Askrypt", icon)?;
        let tx_quit = tx.clone();
        tray.add_menu_item("Open", move || {
            let _ = tx.send(TrayEvent::Open);
        })?;
        tray.add_menu_item("Exit", move || {
            let _ = tx_quit.send(TrayEvent::Quit);
        })?;

        Ok(Self {
            _tray_icon: tray,
            receiver: rx,
        })
    }
}
