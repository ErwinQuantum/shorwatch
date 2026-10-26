//! The `SHORWATCH` banner, in a deep-blue-to-cyan gradient.

use super::style::{dim, gradient, paint};

/// Block letters, three rows high.
const LETTERS: [&str; 3] = [
    "▄▀▀ █ █ ▄▀▄ █▀▄ █   █ ▄▀▄ ▀█▀ ▄▀▀ █ █",
    " ▀▄ █▀█ █ █ █▀▄ █ █ █ █▀█  █  █   █▀█",
    "▀▀  ▀ ▀  ▀  ▀ ▀  ▀ ▀  ▀ ▀  ▀   ▀▀ ▀ ▀",
];

/// The banner, ending with a tagline and the version.
pub fn banner(version: &str) -> String {
    let width = LETTERS.iter().map(|l| l.chars().count()).max().unwrap_or(1);
    let mut out = String::new();
    for row in LETTERS {
        for (column, ch) in row.chars().enumerate() {
            #[allow(clippy::cast_precision_loss)] // banner columns are tiny
            let t = column as f32 / (width - 1).max(1) as f32;
            out.push_str(&paint(ch, gradient(t)));
        }
        out.push('\n');
    }
    out.push_str(&paint(
        format!("  post-quantum crypto scanner · v{version}\n"),
        dim(),
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_is_three_rows_plus_tagline() {
        let plain = anstream::adapter::strip_str(&banner("1.2.3")).to_string();
        assert_eq!(plain.lines().count(), 4);
        assert!(plain.ends_with("v1.2.3\n"), "{plain}");
    }

    #[test]
    fn banner_uses_truecolor() {
        assert!(banner("1.2.3").contains("\x1b[38;2;"));
    }
}
