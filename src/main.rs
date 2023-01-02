// use gtk4::prelude::*;
// use gtk4::{Application, ApplicationWindow, Button};
// const APP_ID: &str = "org.gtk_rs.cryptotool";

// fn main() {
//     // Create a new application
//     let app = Application::builder().application_id(APP_ID).build();
//     app.connect_activate(build_ui);
//     app.run();
// }

// fn build_ui(app: &Application) {
//     // Create a button with label and margins
//     let button = Button::builder()
//         .label("Press me!")
//         .build();

//     // Connect to "clicked" signal of `button`
//     button.connect_clicked(move |button| {
//         // Set the label to "Hello World!" after the button has been clicked on
//         button.set_label("Hello World!");
//     });

//     // Create a window
//     let window = ApplicationWindow::builder()
//         .application(app)
//         .title("My GTK App")
//         .child(&button)
//         .build();
//     window.set_default_size(500, 500);

//     // Present window
//     window.present();
// }

pub fn main(){}