# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial repository layout (5-crate workspace).
- `shorwatch-core`: intermediate model, rule model with validation (Shor-category rules cannot carry an auto-fix) and evaluation engine with hybrid-scheme detection.
- `shorwatch-langs`: Java frontend (tree-sitter) resolving receiver types and same-file `final` constants.
- `shorwatch-rules`: YAML loader and the first rule, `java.crypto.rsa`.
