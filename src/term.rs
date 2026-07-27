use std::io::Write;

pub fn window_title_set(title: &str) {
    if atty::is(atty::Stream::Stdout) {
        crossterm::queue!(std::io::stdout(), crossterm::terminal::SetTitle(title)).unwrap();
        // Special escape sequence for Konsole's tab titles
        print!("\x1b]30;{}\x07", title);
        std::io::stdout().flush().unwrap();
    }
}

pub fn window_title_reset() {
    if atty::is(atty::Stream::Stdout) {
        crossterm::queue!(std::io::stdout(), crossterm::terminal::SetTitle("")).unwrap();
        // Special escape sequence for Konsole's tab titles
        // Since it isn't possible to reset the tab title to its
        // original value, we set it to the Konsole default
        // even if it wasn't this prior to the task.
        print!("\x1b]30;%d : %n\x07");
        std::io::stdout().flush().unwrap();
    }
}
