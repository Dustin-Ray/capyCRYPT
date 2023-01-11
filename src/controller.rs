use std::rc::Rc;
use gtk4::traits::{ButtonExt, FixedExt};
use gtk4::prelude::TextViewExt;
use gtk4::prelude::TextBufferExt;
use gtk4::prelude::WidgetExt;
use gtk4::prelude::ToVariant;
use crate::{get_notepad_data, add_action, AppCtx, model::shake_functions::compute_sha3_hash, macros::button_macros};

/// Sets up buttons for main window.
pub fn setup_buttons(ctx: &AppCtx, tv: &Rc<gtk4::TextView>) {

    let mut buttons = Vec::new();
    let labels = ["Compute Hash", "Compute Tag", "Encrypt With Password", "Decrypt With Password",
    "Generate Keypair", "Encrypt With Key", "Decrypt With Key", "Sign With Key", "Verify Signature"];
    
    // Iteratively add buttons to ctx
    for i in 0..labels.len(){
        let button = gtk4::Button::new();
        button.set_label(labels[i]);
        buttons.push(button); //add buttons to list so they can be turned on/off later
        ctx.fixed.put(&buttons[i], 40.0, 80.0 + i as f64 *45.0);
    }

    // Compute SHA3 Digest
    let tv2 = tv.clone();
    buttons[0].connect_clicked(move |sha_3_button| {
        let notepad_data = button_macros::get_notepad_data!(tv2);
        let result = hex::encode(compute_sha3_hash(notepad_data));
        add_action!(sha_3_button, result);
    });

    // Compute keyed message hash
    let tv3 = tv.clone();
    buttons[1].connect_clicked(move |msg_tag_button| {
        let notepad_data = get_notepad_data!(tv3);
        let result = hex::encode(compute_sha3_hash(notepad_data));
        add_action!(msg_tag_button, result);
    });
    
}