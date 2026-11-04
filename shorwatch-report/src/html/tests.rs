use super::*;
use crate::fixtures::scan;

fn data(html: &str) -> serde_json::Value {
    let start = html
        .find(r#"<script type="application/json" id="shorwatch-data">"#)
        .unwrap();
    let body = &html[start..];
    let body = &body[body.find('>').unwrap() + 1..body.find("</script>").unwrap()];
    serde_json::from_str(body).unwrap()
}

#[test]
fn embeds_styles_script_and_data_in_one_file() {
    let html = render(&scan());
    assert!(html.starts_with("<!doctype html>"));
    assert!(!html.contains("{{"), "a placeholder was left unfilled");
    assert!(
        !html.contains("http://") && !html.contains("<link"),
        "nothing loads from the network"
    );
    let data = data(&html);
    assert_eq!(data["summary"]["findings"], 5);
    assert_eq!(data["findings"].as_array().unwrap().len(), 5);
}

#[test]
fn findings_carry_their_code_and_flow_lines() {
    let data = data(&render(&scan()));
    let rsa = &data["findings"][0];
    assert_eq!(rsa["snippet"]["first_line"], 3);
    assert!(
        rsa["snippet"]["lines"][2]
            .as_str()
            .unwrap()
            .contains("getInstance(\"RSA\")")
    );

    let test = &data["findings"][4];
    assert_eq!(test["flow"].as_array().unwrap().len(), 2);
    assert_eq!(test["flow_lines"][0], "        return fixture(\"RSA\");");
}

#[test]
fn source_text_cannot_close_the_data_script() {
    let mut scan = scan();
    let path = scan.findings[0].path.clone();
    scan.sources.insert(
        path,
        "\n\n\n\n    x = \"</script><img src=x onerror=alert(1)>\";\n".into(),
    );
    let html = render(&scan);
    let data_script = &html[html.find("id=\"shorwatch-data\"").unwrap()..];
    let data_script = &data_script[..data_script.find("</script>").unwrap()];
    assert!(!data_script.contains("<img"));
    assert_eq!(
        data(&html)["findings"][0]["snippet"]["lines"][2],
        "    x = \"</script><img src=x onerror=alert(1)>\";"
    );
}

#[test]
fn findings_know_their_project() {
    let mut scan = scan();
    scan.projects = vec![
        crate::Project {
            name: "auth".into(),
            root: "src/main".into(),
            files_scanned: 9,
        },
        crate::Project {
            name: "auth-tests".into(),
            root: "src/test".into(),
            files_scanned: 3,
        },
    ];
    let data = data(&render(&scan));
    assert_eq!(data["projects"][1]["name"], "auth-tests");
    assert_eq!(data["findings"][0]["project"], 0);
    assert_eq!(data["findings"][4]["project"], 1);
}

#[test]
fn libraries_travel_in_the_data_beside_the_findings() {
    let mut scan = scan();
    assert_eq!(data(&render(&scan))["dependencies"], serde_json::json!([]));
    scan.dependencies = crate::fixtures::dependencies();
    let data = data(&render(&scan));
    assert_eq!(data["findings"].as_array().unwrap().len(), 5);
    assert_eq!(data["dependencies"].as_array().unwrap().len(), 4);
    assert_eq!(data["dependencies"][0]["library"], "BouncyCastle");
    assert_eq!(
        data["dependencies"][0]["post_quantum"]["support"],
        "too_old"
    );
}
