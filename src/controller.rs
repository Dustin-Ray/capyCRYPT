// pub mod buttons{
//     use crate::{AppCtx};
//     use gtk4::prelude::*;
    
//     ///Creates the buttons with labels for the main window.
//     pub fn create_buttons(ctx: &mut AppCtx) {

//         let labels = ["Compute Hash", "Compute Tag", "Encrypt With Password", "Decrypt With Password",
// 		"Generate Keypair", "Encrypt With Key", "Decrypt With Key", "Sign With Key", "Verify Signature"];

//         for i in 0..labels.len(){
//             let button = gtk4::Button::new();
//             button.set_label(labels[i]);
//             ctx.buttons.push(button); //add buttons to list so they can be turned on/off later
//             ctx.fixed.put(&ctx.buttons[i], 40.0, 80.0 + i as f64 *45.0);
//         }
        
//     }


// }