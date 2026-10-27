//! The terminal palette, in one place. Renderers always emit ANSI escapes;
//! the CLI writes through `anstream`, which strips them when the output is
//! not a terminal or `NO_COLOR` is set.

use owo_colors::{OwoColorize, Style};
use shorwatch_core::{Severity, Status};

/// Deep blue to cyan, the banner gradient.
pub(crate) const GRADIENT: [(u8, u8, u8); 2] = [(30, 58, 138), (34, 211, 238)];

const ACCENT: (u8, u8, u8) = (56, 189, 248);
const DIM: (u8, u8, u8) = (100, 116, 139);

fn rgb((r, g, b): (u8, u8, u8)) -> Style {
    Style::new().truecolor(r, g, b)
}

pub(crate) fn accent() -> Style {
    rgb(ACCENT)
}

pub(crate) fn dim() -> Style {
    rgb(DIM)
}

pub(crate) fn bold() -> Style {
    Style::new().bold()
}

/// Colour at `t` (0.0..=1.0) along [`GRADIENT`].
pub(crate) fn gradient(t: f32) -> Style {
    let [(r0, g0, b0), (r1, g1, b1)] = GRADIENT;
    let mix = |a: u8, b: u8| {
        let value = f32::from(a) + (f32::from(b) - f32::from(a)) * t.clamp(0.0, 1.0);
        // Rounded and clamped to 0..=255 above, so the cast cannot truncate.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let value = value.round() as u8;
        value
    };
    Style::new().truecolor(mix(r0, r1), mix(g0, g1), mix(b0, b1))
}

/// ` HIGH ` as a coloured badge, the label padded to `width` for columns.
pub(crate) fn severity_badge(severity: Severity, width: usize) -> String {
    let (label, (r, g, b)) = match severity {
        Severity::Critical => ("CRITICAL", (190, 18, 60)),
        Severity::High => ("HIGH", (220, 38, 38)),
        Severity::Medium => ("MEDIUM", (217, 119, 6)),
        Severity::Low => ("LOW", (37, 99, 235)),
        Severity::Info => ("INFO", (71, 85, 105)),
    };
    format!(" {label:<width$} ")
        .style(Style::new().white().bold().on_truecolor(r, g, b))
        .to_string()
}

/// A file's mark in the overview: its worst severity, or `◐` when all its
/// findings are already in transition.
pub(crate) fn severity_mark(severity: Severity, in_transition: bool) -> String {
    let (mark, color) = match (in_transition, severity) {
        (true, _) => ("◐", (45, 212, 191)),
        (false, Severity::Critical | Severity::High) => ("▲", (248, 113, 113)),
        (false, Severity::Medium) => ("●", (251, 191, 36)),
        (false, Severity::Low | Severity::Info) => ("○", ACCENT),
    };
    paint(mark, rgb(color))
}

/// The status label, padded to `width` for columns.
pub(crate) fn status(status: Status, width: usize) -> String {
    let (label, color) = match status {
        Status::Vulnerable => ("vulnerable", (248, 113, 113)),
        Status::InTransition => ("in transition", (45, 212, 191)),
    };
    format!("{label:<width$}").style(rgb(color)).to_string()
}

pub(crate) fn paint(text: impl std::fmt::Display, style: Style) -> String {
    text.style(style).to_string()
}
