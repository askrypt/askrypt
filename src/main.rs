#![windows_subsystem = "windows"]

mod app;
mod icon;
mod message;
mod screens;
mod session;
mod settings;
mod tray;
mod ui;

use crate::app::AskryptApp;
use iced::{Theme, window};
use std::path::PathBuf;

pub fn main() {
    let args: Vec<String> = std::env::args().collect();
    let vault_path = if args.len() > 1 {
        Some(PathBuf::from(&args[1]))
    } else {
        None
    };

    let _ = iced::application(
        move || AskryptApp::new(vault_path.clone()),
        AskryptApp::update,
        AskryptApp::view,
    )
    .title(AskryptApp::title)
    .subscription(AskryptApp::subscription)
    .window({
        #[allow(unused_mut)]
        let mut settings = window::Settings {
            icon: Some(load_icon().expect("Failed to load icon")),
            exit_on_close_request: false,
            size: iced::Size::new(1100.0, 850.0),
            ..Default::default()
        };
        #[cfg(target_os = "linux")]
        {
            settings.platform_specific.application_id = String::from("askrypt");
        }
        settings
    })
    .centered()
    .theme(Theme::Light)
    .font(include_bytes!("../static/bootstrap-icons.ttf"))
    .run();
}

fn load_icon() -> Result<window::Icon, window::icon::Error> {
    window::icon::from_file_data(include_bytes!("../static/logo-128.png"), None)
}
