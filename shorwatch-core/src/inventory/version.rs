//! Comparing the versions build files declare. Only the leading numbers
//! count (`1.70`, `7.0.0.RELEASE`, `3.1.5-SNAPSHOT`): a version that is not
//! plainly a number (a range, `latest.release`, `1.+`, an unresolved
//! `${property}`) has no order, and the answer is "unknown", never a guess.

/// The numeric components a version starts with.
pub(crate) fn parse(version: &str) -> Option<Vec<u64>> {
    let version = version.trim();
    if version.contains(['+', '[', ']', '(', ')', ',', '*', '$', ' ']) {
        return None;
    }
    let numeric = version.split(['-', '_']).next().unwrap_or(version);
    let mut parts = Vec::new();
    for part in numeric.split('.') {
        let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            // `7.0.0.RELEASE`: the numbers stop at the first word.
            break;
        }
        parts.push(digits.parse().ok()?);
        if digits.len() != part.len() {
            break;
        }
    }
    (!parts.is_empty()).then_some(parts)
}

/// Whether `version` is `since` or later; `None` when either is not a number.
pub(crate) fn at_least(version: &str, since: &str) -> Option<bool> {
    let (mut version, mut since) = (parse(version)?, parse(since)?);
    let length = version.len().max(since.len());
    version.resize(length, 0);
    since.resize(length, 0);
    Some(version >= since)
}
