use std::rc::Rc;
use cryptotool::AppCtx;
use cryptotool::controller::setup_buttons;
use gio::SimpleAction;
use glib::clone;
use gtk4::prelude::*;
use gtk4::{gio, glib, Application, ApplicationWindow};

const APP_ID: &str = "org.cryptoool";

fn main() {
    let app = Application::builder().application_id(APP_ID).build();
    app.connect_activate(build_ui);
    // Run the application
    app.run();
}

fn build_ui(app: &Application) {
    let ctx = AppCtx{
        fixed: &gtk4::Fixed::new(),
        notepad: &gtk4::TextBuffer::new(None),
    };
    
    let window = ApplicationWindow::builder()
        .application(app)
        .title("CryptoTool v0.2")
        .child(ctx.fixed)
        .default_height(590)
        .default_width(1050)
        .build();

    let action_permute = SimpleAction::new_stateful(
        "permute",
        Some(&str::static_variant_type()),
        &"".to_variant(),
    );

    action_permute.connect_activate(clone!(@weak ctx.notepad as notepad => move |action, in_data| {
        let np_text = in_data
            .expect("Could not get notepad text.")
            .get::<String>()
            .expect("The variant needs to be of type `string`.");
        action.set_state(&np_text.to_variant());
        notepad.set_text(&np_text);
    }));
    
    let tv = Rc::new(gtk4::TextView::new());
    tv.set_buffer(Some(ctx.notepad));
    tv.set_wrap_mode(gtk4::WrapMode::Char);

    let scrollable_textarea = gtk4::ScrolledWindow::new();
    scrollable_textarea.set_child(Some(&*tv));
    scrollable_textarea.set_size_request(440, 450);
    ctx.fixed.put(&scrollable_textarea, 245.0, 80.0);

    setup_buttons(&ctx, &tv);
    window.add_action(&action_permute);
    window.present();

}