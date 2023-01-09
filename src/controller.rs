pub mod buttons{
    use crate::AppCtx;
    use gtk4::prelude::*;


    pub fn create_buttons(ctx: &AppCtx) {

        let b = gtk4::Button::new();
        b.set_label("label");

        ctx.fixed.put(&b, 100.0, 100.0);
        
        
    }




}