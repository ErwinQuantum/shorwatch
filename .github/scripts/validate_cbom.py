"""Validate a CycloneDX 1.6 JSON BOM against the official schema.

Usage: validate_cbom.py <schema-dir> <bom.json>

<schema-dir> holds bom-1.6.schema.json, spdx.schema.json and
jsf-0.82.schema.json from CycloneDX/specification@1.6.
"""
import json
import os
import sys

from jsonschema import Draft7Validator
from referencing import Registry, Resource


def load(path):
    with open(path, encoding="utf-8") as file:
        return json.load(file)


schema_dir, bom_path = sys.argv[1], sys.argv[2]
registry = Registry().with_resources(
    (name, Resource.from_contents(load(os.path.join(schema_dir, name))))
    for name in ("spdx.schema.json", "jsf-0.82.schema.json")
)
validator = Draft7Validator(load(os.path.join(schema_dir, "bom-1.6.schema.json")), registry=registry)

document = load(bom_path)
errors = sorted(validator.iter_errors(document), key=lambda e: list(e.path))
for error in errors:
    print("INVALID at", "/".join(map(str, error.path)), ":", error.message[:200])
print(f"{bom_path}: {len(document.get('components', []))} components, {len(errors)} errors")
sys.exit(1 if errors else 0)
