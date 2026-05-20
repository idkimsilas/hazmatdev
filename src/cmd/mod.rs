use indicatif::{ProgressBar, ProgressState, ProgressStyle};

mod format;
mod open;
mod sanitize;

pub use format::format;
pub use open::open;
pub use sanitize::sanitize;

/// Create the byte-oriented progress bar used by long streaming writes.
pub fn create_progress_bar(upper_limit: u64) -> ProgressBar {
    let pb = ProgressBar::new(upper_limit);

    pb.set_style(
        ProgressStyle::with_template(
            "{spinner} [{elapsed_precise}] [{wide_bar}] {bytes}/{total_bytes} ({eta})",
        )
        .unwrap()
        .with_key(
            "eta",
            |state: &ProgressState, w: &mut dyn std::fmt::Write| {
                write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
            },
        )
        .progress_chars("#>-"),
    );

    pb
}
