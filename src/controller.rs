pub mod buttons{
    use crate::{AppCtx, model::shake_functions::compute_sha3_hash};
    use gtk4::prelude::*;

    ///Creates the buttons with labels for the main window.
    pub fn create_buttons(ctx: &mut AppCtx) {

        let labels = ["Compute Hash", "Compute Tag", "Encrypt With Password", "Decrypt With Password",
		"Generate Keypair", "Encrypt With Key", "Decrypt With Key", "Sign With Key", "Verify Signature"];

        for i in 0..labels.len(){
            let button = gtk4::Button::new();
            button.set_label(labels[i]);
            ctx.buttons.push(button); //add buttons to list so they can be turned on/off later
            ctx.fixed.put(&ctx.buttons[i], 40.0, 80.0 + i as f64 *45.0);
        }

        // ctx.buttons[0].connect
    }

    pub fn set_sha3_hash(ctx: &mut AppCtx) {
        let mut message_bytes = ctx.notepad.text(&ctx.notepad.start_iter(), &ctx.notepad.end_iter(), true).as_bytes().to_vec();
        ctx.notepad.set_text(&hex::encode(compute_sha3_hash(&mut message_bytes)));    
    }


}