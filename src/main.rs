use cryptotool::model::shake_functions::compute_sha3_hash;
use gio::SimpleAction;
use glib::clone;
use gtk4::prelude::*;
use gtk4::{gio, glib, Application, ApplicationWindow, Button};

const APP_ID: &str = "org.cryptoool";

pub struct AppCtx {
    pub fixed: gtk4::Fixed,
    pub notepad: gtk4::TextBuffer,
}

fn main() {
    let app = Application::builder().application_id(APP_ID).build();
    app.connect_activate(build_ui);
    // Run the application
    app.run();
}

fn build_ui(app: &Application) {
    let ctx = AppCtx{
        fixed: gtk4::Fixed::new(),
        notepad: gtk4::TextBuffer::new(None),
    };
    
    let text_view = gtk4::TextView::new();
    text_view.set_buffer(Some(&ctx.notepad));
    text_view.set_wrap_mode(gtk4::WrapMode::Char);

    let scrollable_textarea = gtk4::ScrolledWindow::new();
    scrollable_textarea.set_child(Some(&text_view));
    scrollable_textarea.set_size_request(440, 450);

    // Create a button with label
    let button = Button::builder().label("Compute SHA3 Hash").build();

    // Connect to "clicked" signal of `button`
    button.connect_clicked(move |button| {
 
        let notepad_text = hex::encode(
            compute_sha3_hash(
                &mut text_view.buffer().text(
                    &text_view.buffer().start_iter(), 
                    &text_view.buffer().end_iter(), 
                    false
                ).to_string().as_bytes().to_vec()));
        
        button
            .activate_action("win.permute", Some(&notepad_text.to_variant()))
            .expect("The action does not exist.");
    });

    // let fixed = gtk4::Fixed::new();
    ctx.fixed.put(&button, 40.0, 80.0);
    ctx.fixed.put(&scrollable_textarea, 245.0, 80.0);

    // Create a window, set the title and add `gtk_box` to it
    let window = ApplicationWindow::builder()
        .application(app)
        .title("CryptoTool v0.2")
        .child(&ctx.fixed)
        .default_height(590)
        .default_width(1050)
        .build();

    let action_permute = SimpleAction::new_stateful(
        "permute",
        Some(&str::static_variant_type()),
        &"".to_variant(), //copy added here :(
    );

    action_permute.connect_activate(clone!(@weak ctx.notepad as notepad => move |action, parameter| {
        // Get parameter
        let parameter = parameter
            .expect("Could not get parameter.")
            .get::<String>()
            .expect("The variant needs to be of type `string`.");
        action.set_state(&parameter.to_variant());
        notepad.set_text(&parameter);
    }));

    window.add_action(&action_permute);
    window.present();
}
