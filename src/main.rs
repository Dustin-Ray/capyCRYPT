use std::rc::Rc;
use cryptotool::model::shake_functions::compute_sha3_hash;
use cryptotool::notepad_data;
use gio::SimpleAction;
use glib::clone;
use gtk4::prelude::*;
use gtk4::{gio, glib, Application, ApplicationWindow};

const APP_ID: &str = "org.cryptoool";

pub struct AppCtx<'a> {
    pub fixed: &'a gtk4::Fixed,
    pub notepad: &'a gtk4::TextBuffer,
}

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
    
    let tv = Rc::new(gtk4::TextView::new());
    tv.set_buffer(Some(ctx.notepad));
    tv.set_wrap_mode(gtk4::WrapMode::Char);

    let scrollable_textarea = gtk4::ScrolledWindow::new();
    scrollable_textarea.set_child(Some(&*tv));
    scrollable_textarea.set_size_request(440, 450);

    let buttons = setup_buttons(&ctx);

    // Compute SHA3 Digest
    let tv2 = tv.clone();
    buttons[0].connect_clicked(move |sha_3_button| {

        let notepad = notepad_data!(tv2);
        let result = hex::encode(compute_sha3_hash(notepad));
        sha_3_button
            .activate_action("win.permute", Some(&result.to_variant()))
            .expect("The action does not exist.");
    });

    // Compute keyed message hash
    let tv3 = tv.clone();
    buttons[1].connect_clicked(move |msg_tag_button| {
        
        let notepad_data = 
            &mut tv3.buffer().text(
                &tv3.buffer().start_iter(), 
                &tv3.buffer().end_iter(), 
                false
            ).to_string().as_bytes().to_vec();
            
        let result = hex::encode(compute_sha3_hash(notepad_data));
        
        msg_tag_button
            .activate_action("win.permute", Some(&result.to_variant()))
            .expect("The action does not exist.");
    });


    ctx.fixed.put(&scrollable_textarea, 245.0, 80.0);

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
    window.add_action(&action_permute);
    window.present();






}

pub fn setup_buttons(ctx: &AppCtx) -> Vec<gtk4::Button>{

    let labels = ["Compute Hash", "Compute Tag", "Encrypt With Password", "Decrypt With Password",
    "Generate Keypair", "Encrypt With Key", "Decrypt With Key", "Sign With Key", "Verify Signature"];

    let mut buttons = Vec::new();

    for i in 0..labels.len(){
        let button = gtk4::Button::new();
        button.set_label(labels[i]);
        buttons.push(button); //add buttons to list so they can be turned on/off later
        ctx.fixed.put(&buttons[i], 40.0, 80.0 + i as f64 *45.0);
    }
    buttons
}