//! Report rendering. One module per output format; all consume a [`Report`].

use crate::model::Report;

mod html;
mod json;
mod markdown;
mod terminal;

pub use terminal::print_terminal;

/// Render `report` to a string in the requested machine/document format.
pub fn render(report: &Report, format: Format) -> String {
    match format {
        Format::Json => json::render(report),
        Format::Markdown => markdown::render(report),
        Format::Html => html::render(report),
    }
}

/// Non-terminal output formats (the terminal renderer prints directly).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Markdown,
    Html,
}
