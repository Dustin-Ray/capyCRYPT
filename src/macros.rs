pub mod button_macros {
    /// Gets the text from the notepad and converts it
    /// to a u8 vector.
    #[macro_export]
    macro_rules! get_notepad_data {
        ($tv: ident) => {
            &mut $tv.buffer().text(
                &$tv.buffer().start_iter(), 
                &$tv.buffer().end_iter(), 
                false
            ).to_string().as_bytes().to_vec()
        } 
    } pub(crate) use get_notepad_data;
    
    /// Adds action to current window. 
    /// * button: the button for which the action is attached to
    /// * data: the notepad data attached to the button action
    #[macro_export]
    macro_rules! add_action {
        ($button:expr, $result:expr) => {
            $button.activate_action("win.permute", Some(&$result.to_variant())).expect("The action does not exist.");
        }
    } 
}