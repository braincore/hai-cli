use copypasta_ext::prelude::*;
use copypasta_ext::x11_bin::ClipboardContext as X11BinClipboardContext;
use copypasta_ext::x11_fork::ClipboardContext as X11ForkClipboardContext;

// `copypasta` vanilla was failing to copy on linux/x11.
// This extension works.
pub fn copy_to_clipboard(text: &str) -> bool {
    // X11Fork is faster than X11Bin, so prefer it
    if let Ok(mut x11_fork_ctx) = X11ForkClipboardContext::new() {
        if x11_fork_ctx.set_contents(text.trim().to_owned()).is_ok() {
            return true;
        }
    }
    if let Ok(mut x11_bin_ctx) = X11BinClipboardContext::new() {
        if x11_bin_ctx.set_contents(text.trim().to_owned()).is_ok() {
            return true;
        };
    }
    false
}
