//! Telling test code from production code by project layout: the Maven and
//! Gradle conventions (`src/test`, `src/integrationTest`, Kotlin
//! Multiplatform's `src/jvmTest`, Android's `src/androidTest`), .NET test
//! projects (`Acme.Tests/`), test directories, and test class names.

use std::path::Path;

use shorwatch_core::CodeRole;

/// Directories whose whole content is test code.
const TEST_DIRS: &[&str] = &[
    "test",
    "tests",
    "testsuite",
    "testFixtures",
    "test-fixtures",
    "integration-test",
    "integration-tests",
];

/// Class name suffixes of test classes (JUnit, Surefire and Failsafe).
const TEST_CLASS_SUFFIXES: &[&str] = &["Test", "Tests", "TestCase", "IT", "ITCase"];

/// The role of `path`, given relative to the scanned directory so that the
/// directories above the project (`~/work/tests/my-service`) do not count.
pub fn role(path: &Path) -> CodeRole {
    let parts: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let Some((file, dirs)) = parts.split_last() else {
        return CodeRole::Production;
    };
    let in_test_dir = dirs.iter().enumerate().any(|(i, dir)| {
        TEST_DIRS.contains(&dir.as_str())
            // Gradle source sets: `src/integrationTest`, `src/jvmTest`.
            || (i > 0 && dirs[i - 1] == "src" && (dir.ends_with("Test") || dir.ends_with("Tests")))
            // .NET test projects: `Acme.Tests`, `Acme.UnitTests`, `Acme.Test`.
            || dir.ends_with("Tests")
            || dir.ends_with(".Test")
    });
    let stem = Path::new(file)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let is_test_class = TEST_CLASS_SUFFIXES
        .iter()
        .any(|suffix| stem.len() > suffix.len() && stem.ends_with(suffix));
    if in_test_dir || is_test_class {
        CodeRole::Test
    } else {
        CodeRole::Production
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role_of(path: &str) -> CodeRole {
        role(Path::new(path))
    }

    #[test]
    fn maven_and_gradle_test_source_sets_are_test_code() {
        for path in [
            "src/test/java/com/acme/Keys.java",
            "core/src/test/resources/application.yml",
            "src/integrationTest/kotlin/Flows.kt",
            "src/jvmTest/kotlin/Keys.kt",
            "app/src/androidTest/java/Keys.java",
            "src/testFixtures/java/Keys.java",
            "testsuite/integration/src/main/java/Helper.java",
            "src/Acme.Payments.Tests/SignerTests.cs",
            "tests/Acme.UnitTests/Keys.cs",
            "Acme.Test/Keys.cs",
        ] {
            assert_eq!(role_of(path), CodeRole::Test, "{path}");
        }
    }

    #[test]
    fn test_classes_are_test_code_wherever_they_live() {
        assert_eq!(role_of("src/main/java/KeysTest.java"), CodeRole::Test);
        assert_eq!(role_of("src/main/java/KeyRotationIT.java"), CodeRole::Test);
        assert_eq!(role_of("src/main/kotlin/SignerTests.kt"), CodeRole::Test);
    }

    #[test]
    fn production_code_stays_production() {
        for path in [
            "src/main/java/com/acme/Keys.java",
            "src/main/java/com/acme/testing/Fixtures.java",
            "src/main/java/com/acme/Test.java",
            "src/main/java/com/acme/Attestation.java",
            "src/main/resources/application.yml",
            "Keys.kt",
            "src/Acme.Payments/Signer.cs",
        ] {
            assert_eq!(role_of(path), CodeRole::Production, "{path}");
        }
    }
}
