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
    
    let mut ctx = AppCtx{
        fixed: gtk4::Fixed::new(),
        buttons: Vec::new(),
        notepad: gtk4::TextBuffer::new(None),};

    setup_window(&app, &ctx);
    setup_buttons(&mut ctx);
    setup_notepad(&mut ctx)


}

pub fn setup_window(app: &Application, ctx: &AppCtx) {
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

pub fn setup_buttons(ctx: &mut AppCtx) {
    create_buttons(ctx);
}

pub fn setup_notepad(ctx: &mut AppCtx) {

    let scrollable_text_area = gtk4::ScrolledWindow::new();
    let buf = gtk4::TextBuffer::new(None);
    ctx.notepad = buf;
    let text_view = gtk4::TextView::new();
    text_view.set_wrap_mode(gtk4::WrapMode::Char);
    text_view.set_buffer(Some(&ctx.notepad));
    ctx.notepad.set_text("Enter text or drag and drop file...");
    scrollable_text_area.set_child(Some(&text_view));
    scrollable_text_area.set_size_request(440, 450);
    ctx.fixed.put(&scrollable_text_area, 245.0, 80.0);

}