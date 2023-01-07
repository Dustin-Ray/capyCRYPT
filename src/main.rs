// use gtk4::prelude::*;
// use gtk4::{Application, ApplicationWindow, Button};
// const APP_ID: &str = "org.gtk_rs.cryptotool";

// struct WindowCtx<'a> {
//     win: &'a gtk4::Window,
//     fixed: &'a gtk4::Fixed,
//     notepad: &'a gtk4::TextBuffer,
//     init: bool,
//     status: &'a gtk4::Label,
//     progress_bar: &'a gtk4::ProgressBar,
//     buttons: &'a [gtk4::Button]
// }

// //en
// fn main() {
//     // Create a new application
//     let app = Application::builder().application_id(APP_ID).build();
//     app.connect_activate(setup_window);
    
//     app.run();
// }

// fn setup_window(app: &Application) {    
//     // Create a window
//     let window = ApplicationWindow::builder()
//         .application(app)
//         .title("CryptoTool v0.1")
//         .build();
//     window.set_default_size(1050, 590);
//     // Present window
//     window.present();
// }


// fn new_fixed() -> gtk4::Fixed {
//     let fixed = gtk4::Fixed::new();
//     fixed.set_size_request(1050, 590);
//     fixed
// }

fn main() {}