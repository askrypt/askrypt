use std::sync::mpsc::{self, Receiver};
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayEvent {
    Open,
    Quit,
}

pub struct AppTray {
    _tray_icon: TrayIcon,
    open_item_id: tray_icon::menu::MenuId,
    quit_item_id: tray_icon::menu::MenuId,
}

impl AppTray {
    pub fn new() -> Result<(Self, Receiver<TrayEvent>), Box<dyn std::error::Error>> {
        let (tx, rx) = mpsc::channel();

        // Create menu items
        let open_item = MenuItem::new("Open Askrypt", true, None);
        let quit_item = MenuItem::new("Quit Askrypt", true, None);

        let open_item_id = open_item.id().clone();
        let quit_item_id = quit_item.id().clone();

        // Create menu
        let menu = Menu::new();
        menu.append(&open_item)?;
        menu.append(&quit_item)?;

        // Create a simple icon (32x32 blue square with "A" shape)
        let icon = create_app_icon()?;

        // Build tray icon
        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("Askrypt")
            .with_icon(icon)
            .build()?;

        // Set up menu event handler
        let open_id = open_item_id.clone();
        let quit_id = quit_item_id.clone();

        std::thread::spawn(move || {
            loop {
                if let Ok(event) = MenuEvent::receiver().recv() {
                    if event.id == open_id {
                        let _ = tx.send(TrayEvent::Open);
                    } else if event.id == quit_id {
                        let _ = tx.send(TrayEvent::Quit);
                    }
                }
            }
        });

        Ok((
            Self {
                _tray_icon: tray_icon,
                open_item_id,
                quit_item_id,
            },
            rx,
        ))
    }
}

fn create_app_icon() -> Result<Icon, Box<dyn std::error::Error>> {
    const SIZE: usize = 32;
    let mut rgba = vec![0u8; SIZE * SIZE * 4];

    // Create a simple icon: blue background with a lighter "A" shape
    for y in 0..SIZE {
        for x in 0..SIZE {
            let idx = (y * SIZE + x) * 4;

            // Background color (dark blue)
            let mut r = 30u8;
            let mut g = 60u8;
            let mut b = 114u8;
            let mut a = 255u8;

            // Draw a simple "A" shape in lighter color
            let cx = SIZE / 2;
            let in_a_shape = {
                // Left leg of A
                let left_leg = x >= cx - 10 - (SIZE - y) / 3 && x <= cx - 6 - (SIZE - y) / 3;
                // Right leg of A
                let right_leg = x >= cx + 6 + (SIZE - y) / 3 && x <= cx + 10 + (SIZE - y) / 3;
                // Horizontal bar
                let bar = y >= SIZE / 2 - 2 && y <= SIZE / 2 + 2 && x >= cx - 8 && x <= cx + 8;
                // Top of A
                let top = y <= 6 && x >= cx - 3 && x <= cx + 3;

                (left_leg || right_leg || bar || top) && y >= 4 && y <= SIZE - 4
            };

            if in_a_shape {
                // Lighter color for the "A"
                r = 200;
                g = 220;
                b = 255;
            }

            // Make corners rounded (transparent)
            let corner_dist = 4;
            let is_corner = (x < corner_dist && y < corner_dist)
                || (x >= SIZE - corner_dist && y < corner_dist)
                || (x < corner_dist && y >= SIZE - corner_dist)
                || (x >= SIZE - corner_dist && y >= SIZE - corner_dist);

            if is_corner {
                a = 0;
            }

            rgba[idx] = r;
            rgba[idx + 1] = g;
            rgba[idx + 2] = b;
            rgba[idx + 3] = a;
        }
    }

    Icon::from_rgba(rgba, SIZE as u32, SIZE as u32).map_err(|e| e.into())
}
