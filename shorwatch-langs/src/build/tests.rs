//! The build file frontends on small in-memory files.

use shorwatch_core::ir::{FactKind, SourceUnit};

use super::*;
use crate::Frontend;

/// `(group:artifact, version, scope)` of every dependency, in file order.
fn found(unit: &SourceUnit) -> Vec<(String, Option<String>, Option<String>)> {
    unit.facts()
        .iter()
        .filter_map(|fact| match &fact.kind {
            FactKind::Dependency {
                group,
                artifact,
                version,
                scope,
            } => Some((
                format!("{group}:{artifact}"),
                version.clone(),
                scope.clone(),
            )),
            _ => None,
        })
        .collect()
}

fn dep(
    name: &str,
    version: Option<&str>,
    scope: Option<&str>,
) -> (String, Option<String>, Option<String>) {
    (
        name.to_owned(),
        version.map(str::to_owned),
        scope.map(str::to_owned),
    )
}

fn pom(source: &str) -> SourceUnit {
    MavenFrontend.lower("pom.xml", source).unwrap()
}

fn gradle(source: &str) -> SourceUnit {
    GradleFrontend.lower("build.gradle", source).unwrap()
}

fn catalog(source: &str) -> SourceUnit {
    VersionCatalogFrontend
        .lower("gradle/libs.versions.toml", source)
        .unwrap()
}

mod maven {
    use super::*;

    #[test]
    fn reads_coordinates_scope_and_the_line_of_each_dependency() {
        let unit = pom(r#"<project>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.70</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>"#);
        assert_eq!(
            found(&unit),
            vec![
                dep("org.bouncycastle:bcprov-jdk18on", Some("1.70"), None),
                dep("junit:junit", Some("4.13"), Some("test")),
            ]
        );
        let lines: Vec<u32> = unit.facts().iter().map(|f| f.location.start.line).collect();
        assert_eq!(lines, [3, 8]);
    }

    #[test]
    fn properties_fill_in_the_version() {
        let unit = pom(r#"<project>
  <version>2.5</version>
  <properties><bc.version>1.69</bc.version></properties>
  <dependencies>
    <dependency><groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk18on</artifactId><version>${bc.version}</version></dependency>
    <dependency><groupId>acme</groupId><artifactId>self</artifactId><version>${project.version}</version></dependency>
  </dependencies>
</project>"#);
        assert_eq!(
            found(&unit),
            vec![
                dep("org.bouncycastle:bcprov-jdk18on", Some("1.69"), None),
                dep("acme:self", Some("2.5"), None),
            ]
        );
    }

    #[test]
    fn a_version_the_file_does_not_say_is_none() {
        let unit = pom(r#"<project><dependencies>
    <dependency><groupId>a</groupId><artifactId>managed</artifactId></dependency>
    <dependency><groupId>a</groupId><artifactId>elsewhere</artifactId><version>${from.the.parent}</version></dependency>
</dependencies></project>"#);
        assert_eq!(
            found(&unit),
            vec![dep("a:managed", None, None), dep("a:elsewhere", None, None)]
        );
    }

    #[test]
    fn a_parent_version_is_the_projects_when_it_sets_none() {
        let unit = pom(r#"<project>
  <parent><groupId>acme</groupId><artifactId>p</artifactId><version>3.0</version></parent>
  <dependencies><dependency><groupId>acme</groupId><artifactId>x</artifactId><version>${project.version}</version></dependency></dependencies>
</project>"#);
        assert_eq!(found(&unit), vec![dep("acme:x", Some("3.0"), None)]);
    }

    #[test]
    fn managed_dependencies_are_marked_and_plugin_ones_left_out() {
        let unit = pom(r#"<project>
  <dependencyManagement><dependencies>
    <dependency><groupId>a</groupId><artifactId>bom</artifactId><version>1</version></dependency>
  </dependencies></dependencyManagement>
  <build><plugins><plugin>
    <dependencies><dependency><groupId>p</groupId><artifactId>plugin-dep</artifactId><version>9</version></dependency></dependencies>
  </plugin></plugins></build>
</project>"#);
        assert_eq!(found(&unit), vec![dep("a:bom", Some("1"), Some("managed"))]);
    }

    #[test]
    fn entities_and_comments_are_handled() {
        let unit = pom(r#"<project><dependencies>
  <!-- <dependency><groupId>commented</groupId><artifactId>out</artifactId></dependency> -->
  <dependency><groupId>a&amp;b</groupId><artifactId><![CDATA[c]]></artifactId><version>1</version></dependency>
</dependencies></project>"#);
        assert_eq!(found(&unit), vec![dep("a&b:c", Some("1"), None)]);
    }

    #[test]
    fn a_file_that_is_not_xml_is_refused() {
        assert!(
            MavenFrontend
                .lower("pom.xml", "<project><dependencies></project>")
                .is_err()
        );
    }

    #[test]
    fn nesting_beyond_any_real_pom_is_refused() {
        let source = format!("{}{}", "<a>".repeat(5_000), "</a>".repeat(5_000));
        assert!(matches!(
            MavenFrontend.lower("pom.xml", &source),
            Err(crate::LangError::TooDeep(..))
        ));
    }

    #[test]
    fn external_entities_are_never_read() {
        let unit = pom(r#"<?xml version="1.0"?>
<!DOCTYPE project [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<project><dependencies><dependency><groupId>a</groupId><artifactId>b</artifactId><version>&x;</version></dependency></dependencies></project>"#);
        // The reference resolves to nothing: no file is opened.
        assert_eq!(found(&unit), vec![dep("a:b", None, None)]);
    }
}

mod gradle {
    use super::*;

    #[test]
    fn groovy_strings_with_and_without_parentheses() {
        let unit = gradle(
            "dependencies {\n  implementation 'org.bouncycastle:bcprov-jdk18on:1.70'\n  testImplementation(\"junit:junit:4.13\")\n}\n",
        );
        assert_eq!(
            found(&unit),
            vec![
                dep(
                    "org.bouncycastle:bcprov-jdk18on",
                    Some("1.70"),
                    Some("implementation")
                ),
                dep("junit:junit", Some("4.13"), Some("testImplementation")),
            ]
        );
        assert_eq!(unit.facts()[0].location.start.line, 2);
    }

    #[test]
    fn named_arguments_in_groovy_and_kotlin() {
        let unit = gradle(
            "implementation group: 'com.nimbusds', name: 'nimbus-jose-jwt', version: '9.37'\nimplementation(group = \"io.jsonwebtoken\", name = \"jjwt-api\", version = \"0.12.5\")\n",
        );
        assert_eq!(
            found(&unit),
            vec![
                dep(
                    "com.nimbusds:nimbus-jose-jwt",
                    Some("9.37"),
                    Some("implementation")
                ),
                dep(
                    "io.jsonwebtoken:jjwt-api",
                    Some("0.12.5"),
                    Some("implementation")
                ),
            ]
        );
    }

    #[test]
    fn variables_the_script_defines_fill_in_the_version() {
        let unit = gradle(
            "val bcVersion = \"1.69\"\next { jsch = '0.1.55' }\ndependencies {\n  implementation(\"org.bouncycastle:bcprov-jdk18on:$bcVersion\")\n  implementation \"com.jcraft:jsch:${jsch}\"\n  implementation 'a:single:$literal'\n}\n",
        );
        assert_eq!(
            found(&unit),
            vec![
                dep(
                    "org.bouncycastle:bcprov-jdk18on",
                    Some("1.69"),
                    Some("implementation")
                ),
                dep("com.jcraft:jsch", Some("0.1.55"), Some("implementation")),
                // Single quotes do not interpolate: the text is the version.
                dep("a:single", Some("$literal"), Some("implementation")),
            ]
        );
    }

    #[test]
    fn a_variable_it_does_not_define_leaves_the_version_unknown() {
        let unit = gradle("implementation(\"a:b:$fromSomewhereElse\")\nimplementation(\"a:c\")\n");
        assert_eq!(
            found(&unit),
            vec![
                dep("a:b", None, Some("implementation")),
                dep("a:c", None, Some("implementation")),
            ]
        );
    }

    #[test]
    fn platforms_several_arguments_and_extensions() {
        let unit = gradle(
            "implementation(platform(\"org.springframework.boot:spring-boot-dependencies:3.2.0\"))\napi 'a:one:1', 'b:two:2@jar'\n",
        );
        assert_eq!(
            found(&unit),
            vec![
                dep(
                    "org.springframework.boot:spring-boot-dependencies",
                    Some("3.2.0"),
                    Some("implementation")
                ),
                dep("a:one", Some("1"), Some("api")),
                dep("b:two", Some("2"), Some("api")),
            ]
        );
    }

    #[test]
    fn variant_configurations_count() {
        let unit =
            gradle("androidTestImplementation(\"a:b:1\")\ndebugApi 'c:d:2'\nkapt(\"e:f:3\")\n");
        assert_eq!(found(&unit).len(), 3);
    }

    #[test]
    fn what_is_not_a_plain_dependency_is_left_out() {
        let unit = gradle(
            "plugins { id(\"org.jetbrains.kotlin.jvm\") version \"1.9.0\" }\ndependencies {\n  implementation(project(\":core\"))\n  implementation(libs.bcprov)\n  implementation(kotlin(\"stdlib\"))\n  implementation(files(\"lib/x.jar\"))\n}\nproject.dependencies.implementation(\"a:b:1\")\n",
        );
        assert!(found(&unit).is_empty(), "{:?}", found(&unit));
    }

    #[test]
    fn comments_hide_nothing_real_and_show_nothing_fake() {
        let unit = gradle(
            "// implementation 'commented:out:1'\n/* implementation 'also:out:2'\n implementation 'still:out:3' */\nimplementation 'real:one:4' // trailing\n",
        );
        assert_eq!(
            found(&unit),
            vec![dep("real:one", Some("4"), Some("implementation"))]
        );
        assert_eq!(unit.facts()[0].location.start.line, 4);
    }

    #[test]
    fn a_string_that_is_never_closed_ends_at_its_line() {
        let unit = gradle("implementation 'broken:one:1\nimplementation 'fine:two:2'\n");
        assert_eq!(found(&unit).len(), 2);
    }
}

mod version_catalog {
    use super::*;

    const CATALOG: &str = r#"# libraries
[versions]
bc = "1.70"
nimbus = { strictly = "9.37" }

[libraries]
bcprov = { module = "org.bouncycastle:bcprov-jdk18on", version.ref = "bc" }
nimbus = { group = "com.nimbusds", name = "nimbus-jose-jwt", version = { ref = "nimbus" } }
jsch = "com.jcraft:jsch:0.1.55"
junit = { module = "junit:junit", version = "4.13" } # inline comment
managed = { module = "a:managed" }
missing = { module = "a:missing", version.ref = "nope" }

[plugins]
kotlin = { id = "org.jetbrains.kotlin.jvm", version = "1.9.0" }
"#;

    #[test]
    fn libraries_get_their_version_through_version_ref() {
        assert_eq!(
            found(&catalog(CATALOG)),
            vec![
                dep("org.bouncycastle:bcprov-jdk18on", Some("1.70"), None),
                dep("com.nimbusds:nimbus-jose-jwt", Some("9.37"), None),
                dep("com.jcraft:jsch", Some("0.1.55"), None),
                dep("junit:junit", Some("4.13"), None),
                dep("a:managed", None, None),
                dep("a:missing", None, None),
            ]
        );
    }

    #[test]
    fn each_library_is_located_at_its_line() {
        let unit = catalog(CATALOG);
        assert_eq!(unit.facts()[0].location.start.line, 7);
        assert_eq!(unit.facts()[2].location.start.line, 9);
    }

    #[test]
    fn garbage_is_skipped_not_fatal() {
        let unit = catalog("[libraries]\n= = =\nx = { module = \n y = {{{\nok = \"a:b:1\"\n");
        assert_eq!(found(&unit), vec![dep("a:b", Some("1"), None)]);
    }
}

mod nuget {
    use super::*;

    fn project(source: &str) -> SourceUnit {
        NuGetFrontend.lower("App.csproj", source).unwrap()
    }

    #[test]
    fn reads_package_references_with_a_version_attribute_or_element() {
        let unit = project(
            r#"<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="BouncyCastle.Cryptography" Version="2.4.0" />
    <PackageReference Include="Microsoft.IdentityModel.Tokens">
      <Version>8.0.1</Version>
    </PackageReference>
    <PackageReference Include="Newtonsoft.Json" VersionOverride="13.0.3" />
  </ItemGroup>
</Project>"#,
        );
        assert_eq!(
            found(&unit),
            vec![
                dep(":BouncyCastle.Cryptography", Some("2.4.0"), None),
                dep(":Microsoft.IdentityModel.Tokens", Some("8.0.1"), None),
                dep(":Newtonsoft.Json", Some("13.0.3"), None),
            ]
        );
        assert_eq!(unit.facts()[0].location.start.line, 3);
        assert_eq!(unit.facts()[1].location.start.line, 4);
    }

    #[test]
    fn a_reference_without_a_version_is_still_a_reference() {
        // Central package management: the version lives in another file.
        let unit = project(
            r#"<Project><ItemGroup><PackageReference Include="A.B" /></ItemGroup></Project>"#,
        );
        assert_eq!(found(&unit), vec![dep(":A.B", None, None)]);
    }

    #[test]
    fn central_versions_are_managed() {
        let unit = NuGetFrontend
            .lower(
                "Directory.Packages.props",
                r#"<Project>
  <PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="BouncyCastle.Cryptography" Version="2.5.0" />
    <GlobalPackageReference Include="Analyzer.X" Version="1.0.0" />
  </ItemGroup>
</Project>"#,
            )
            .unwrap();
        assert_eq!(
            found(&unit),
            vec![
                dep(":BouncyCastle.Cryptography", Some("2.5.0"), Some("managed")),
                dep(":Analyzer.X", Some("1.0.0"), Some("global")),
            ]
        );
    }

    #[test]
    fn a_property_version_is_resolved_and_an_unknown_one_is_left_out() {
        let unit = project(
            r#"<Project>
  <PropertyGroup><BcVersion>2.4.0</BcVersion></PropertyGroup>
  <ItemGroup>
    <PackageReference Include="A" Version="$(BcVersion)" />
    <PackageReference Include="B" Version="$(FromTheBuild)" />
  </ItemGroup>
</Project>"#,
        );
        assert_eq!(
            found(&unit),
            vec![dep(":A", Some("2.4.0"), None), dep(":B", None, None)]
        );
    }

    #[test]
    fn an_exact_version_in_brackets_is_that_version_and_a_range_is_not_guessed() {
        let unit = project(
            r#"<Project><ItemGroup>
  <PackageReference Include="A" Version="[10.0.8]" />
  <PackageReference Include="B" Version="[1.0,2.0)" />
  <PackageReference Include="C" Version="1.*" />
</ItemGroup></Project>"#,
        );
        assert_eq!(
            found(&unit),
            vec![
                dep(":A", Some("10.0.8"), None),
                dep(":B", Some("[1.0,2.0)"), None),
                dep(":C", Some("1.*"), None),
            ]
        );
    }

    #[test]
    fn packages_config_lists_the_older_format() {
        let unit = NuGetFrontend
            .lower(
                "packages.config",
                r#"<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Portable.BouncyCastle" version="1.9.0" targetFramework="net48" />
</packages>"#,
            )
            .unwrap();
        assert_eq!(
            found(&unit),
            vec![dep(":Portable.BouncyCastle", Some("1.9.0"), None)]
        );
    }

    #[test]
    fn items_that_are_not_packages_are_ignored() {
        let unit = project(
            r#"<Project><ItemGroup>
  <ProjectReference Include="..\Core\Core.csproj" />
  <Reference Include="System.Core" />
  <PackageReference Update="Existing" Version="1.0" />
</ItemGroup></Project>"#,
        );
        assert!(found(&unit).is_empty());
    }

    #[test]
    fn a_broken_file_is_an_error_not_a_panic() {
        assert!(
            NuGetFrontend
                .lower("A.csproj", "<Project><ItemGroup></Project>")
                .is_err()
        );
    }
}

#[test]
fn files_are_found_by_name_not_by_extension() {
    use std::path::Path;
    for (path, language) in [
        ("svc/pom.xml", shorwatch_core::Language::Maven),
        ("svc/build.gradle", shorwatch_core::Language::Gradle),
        ("svc/build.gradle.kts", shorwatch_core::Language::Gradle),
        (
            "gradle/libs.versions.toml",
            shorwatch_core::Language::VersionCatalog,
        ),
        ("src/App/App.csproj", shorwatch_core::Language::NuGet),
        ("src/packages.config", shorwatch_core::Language::NuGet),
        ("Directory.Packages.props", shorwatch_core::Language::NuGet),
    ] {
        let frontend = crate::for_path(Path::new(path)).unwrap();
        assert_eq!(frontend.language(), language, "{path}");
    }
    for path in [
        "svc/other.xml",
        "Cargo.toml",
        "settings.gradle",
        "svc/pom.xml.bak",
    ] {
        assert!(crate::for_path(Path::new(path)).is_none(), "{path}");
    }
    // Extensions still work.
    assert!(crate::for_path(Path::new("A.java")).is_some());
}
