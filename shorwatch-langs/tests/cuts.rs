//! No frontend may panic on a file, however it is cut or encoded: scanned
//! files are untrusted, and a panic costs the whole scan (a JSON reader once
//! split a no-break space in half). Each sample mixes ASCII with multi-byte
//! characters and whitespace; every prefix and suffix at a character boundary
//! is lowered as text, and every byte prefix as bytes (invalid UTF-8 is
//! decoded as Latin-1 by the frontends).

use std::path::Path;

const AWKWARD: &str = "\u{a0}\u{e9}\u{1F600}\u{feff}\u{3000}";

/// A small file per frontend, named so `for_path` picks that frontend.
fn samples() -> Vec<(&'static str, String)> {
    let a = AWKWARD;
    vec![
        (
            "A.java",
            format!(
                "import javax.crypto.Cipher; class A {{ String s = \"{a}\"; void m() {{ Cipher.getInstance(\"RSA{a}\"); }} }}"
            ),
        ),
        (
            "A.kt",
            format!(
                "import javax.crypto.Cipher\nclass A {{ val s = \"{a}\"\n fun m() {{ Cipher.getInstance(\"RSA{a}\") }} }}"
            ),
        ),
        (
            "A.cs",
            format!(
                "using System.Security.Cryptography; class A {{ string s = \"{a}\"; void M(IConfiguration c) {{ RSA.Create(2048); c[\"K{a}\"]; }} }}"
            ),
        ),
        (
            "a.yml",
            format!("a:\n  b: \"{a}\"\n  c: [x, '{a}', {{ d: e }}]\n# {a}\n"),
        ),
        (
            "a.properties",
            format!("a.b={a}\nc\\u00e9 = {a}\\\n  more\n"),
        ),
        (
            "appsettings.json",
            format!("{{\"a\":{a}\"b\", \"c\": [1, null, \"{a}\"], /* {a} */ \"d\": {a}}}"),
        ),
        (
            "pom.xml",
            format!(
                "<project><properties><v>{a}</v></properties><dependencies><dependency><groupId>g{a}</groupId><artifactId>a</artifactId><version>${{v}}</version></dependency></dependencies></project>"
            ),
        ),
        (
            "build.gradle",
            format!(
                "dependencies {{ implementation \"g{a}:a:1.0\"\n implementation(group: 'g', name: 'a{a}', version: v) }}"
            ),
        ),
        (
            "libs.versions.toml",
            format!(
                "[versions]\nv = \"{a}\"\n[libraries]\nx = {{ module = \"g:a{a}\", version.ref = \"v\" }}\n"
            ),
        ),
        (
            "App.csproj",
            format!(
                "<Project><PropertyGroup><V>{a}</V></PropertyGroup><ItemGroup><PackageReference Include=\"P{a}\" Version=\"$(V)\" /></ItemGroup></Project>"
            ),
        ),
    ]
}

#[test]
fn no_frontend_panics_on_any_cut_of_awkward_text() {
    for (name, text) in samples() {
        let frontend = shorwatch_langs::for_path(Path::new(name))
            .unwrap_or_else(|| panic!("no frontend for {name}"));
        let cuts = text.char_indices().map(|(i, _)| i).chain([text.len()]);
        for cut in cuts {
            let _ = frontend.lower(name, &text[..cut]);
            let _ = frontend.lower(name, &text[cut..]);
        }
    }
}

#[test]
fn no_frontend_panics_on_any_byte_prefix() {
    for (name, text) in samples() {
        let frontend = shorwatch_langs::for_path(Path::new(name)).unwrap();
        let bytes = text.as_bytes();
        for cut in 0..=bytes.len() {
            let _ = frontend.lower_bytes(name, bytes[..cut].to_vec());
        }
    }
}
