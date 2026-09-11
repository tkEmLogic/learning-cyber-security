#!/usr/bin/env python3

import json
import pathlib
import sys

import yaml
from jsonschema import Draft202012Validator

root = pathlib.Path(__file__).resolve().parents[1]

for path in sorted((root / "evidence").rglob("*.json")):
    with path.open(encoding="utf-8") as handle:
        json.load(handle)

with (root / "evidence/schemas/course-manifest.schema.json").open(encoding="utf-8") as handle:
    manifest_schema = json.load(handle)
with (root / "course.yml").open(encoding="utf-8") as handle:
    manifest = yaml.safe_load(handle)
Draft202012Validator(manifest_schema).validate(manifest)

with (root / "evidence/schemas/tier-00-evidence.schema.json").open(encoding="utf-8") as handle:
    evidence_schema = json.load(handle)
validator = Draft202012Validator(evidence_schema)
for base in ("evidence/templates/tier-00", "evidence/examples/tier-00"):
    for path in sorted((root / base).glob("*.json")):
        with path.open(encoding="utf-8") as handle:
            validator.validate(json.load(handle))

print("JSON syntax and schema checks passed.")
sys.exit(0)
