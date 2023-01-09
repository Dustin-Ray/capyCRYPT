use cryptotool::AppCtx;
use cryptotool::controller::buttons::create_buttons;
use gtk4::prelude::*;
use gtk4::{Application, ApplicationWindow};

const APP_ID: &str = "org.gtk_rs.CryptoTool";

fn main() {
    // Create a new application
    let app = Application::builder().application_id(APP_ID).build();
    // Connect to "activate" signal of `app`
    app.connect_activate(build_ui);
    // Run the application
    app.run();
}

fn build_ui(app: &Application) {
    
    let ctx = AppCtx{fixed: gtk4::Fixed::new()};

    setup_buttons(&ctx);
   // Create a window and set the title
    let window = ApplicationWindow::builder()
        .application(app)
        .title("CryptoTool v0.2")
        .child(&ctx.fixed)
        .build();
    window.set_default_size(1050, 590);
    
    // Present window
    window.present();
}


pub fn setup_buttons(ctx: &AppCtx) {
    create_buttons(ctx);
}