"""MITRE D3FEND field-projection preprocessor.

Reads five raw JSON files produced by the D3FEND crawler
(`data-acquisition/mitre-defend/{techniques,tactics,artifacts,weaknesses,
mappings}/latest.json`) and writes four trimmed JSON files: one per entity
type (`technique`/`tactic`/`artifact`), plus one `relationships.json`
covering every edge in the dataset. `offensive-techniques/latest.json` is
read by the crawler but not by this script (see below); `weaknesses/
latest.json` is read here for its embedded `child_of`/`weakness_of`/
`may_be_weakness_of` relationships but no longer produces its own entity
file either -- both `offensive-technique` and `weakness` records are
mirrors of another source in this project (ATT&CK techniques, CWE
weaknesses respectively) with no local entity file of their own anymore;
join their relationship endpoints directly against
`data-preprocessing/mitre-attack/techniques.json` /
`data-preprocessing/CWE/weaknesses.json` by `id`.

Both mirrors were checked before dropping: all 835 `offensive-technique`
ids and all 943 `weakness` ids exist in their respective source. For
`offensive-technique`, D3FEND's `definition` was consistently just a
truncated prefix of ATT&CK's fuller `description` -- pure data loss, no
unique content. `weakness` was closer: 97.7% of `definition`s were
identical to CWE's `Description` after whitespace-normalizing, but the
remainder had drifted independently in both directions (D3FEND fuller in
17 cases, CWE fuller in 5), plus a handful of D3FEND-only `synonyms` and a
single `comment` recovering content CWE's own preprocessor discards
elsewhere. Dropped anyway, accepting that small residue, for the same
"match id directly" reason as `offensive-technique`.

D3FEND's own JSON is JSON-LD, not STIX -- every record is keyed by an `@id`
like `"d3f:CWE-1004"` or `"d3f:T1055.001"`, and most fields carry an
`rdfs:`/`d3f:`/`owl:`/`skos:` namespace prefix in the key itself (e.g.
`"rdfs:label"`, `"d3f:synonym"`). Unlike CWE/CAPEC/ATT&CK -- where this
project's preprocessors keep the source field names verbatim, because
they're already clean identifiers -- every field here is renamed to a
plain snake_case attribute (`name`, `definition`, `synonyms`, ...): a raw
key containing a literal colon is awkward to carry into a flattened JSON
output, unlike `x_capec_abstraction` or `ExtendedDescription`.

JSON-LD also collapses a cardinality-1 value to a bare scalar instead of a
one-item list (the same quirk CWE's XML-to-JSON conversion has for its own
single-vs-list fields) -- `as_list()` normalizes both shapes. `tactic`
records also carry typed-literal values (`{"@type": "...integer", "@value":
"3"}`) for a couple of fields -- `literal_value()` unwraps those.

`_content_hash`/`_first_seen_at` are dropped from every record: they're
this project's *own* crawler bookkeeping (D3FEND has no native timestamps
at all, per the crawler's README), not domain content. `@type` is dropped
too -- pure OWL/RDF class-membership boilerplate (`"owl:Class"`,
`"owl:NamedIndividual"`), not analytically useful once the record is
already sorted into its own per-type output file.

## Ids double as this dataset's own cross-references

Stripping the fixed `d3f:` namespace prefix from every `@id` (the one
normalization applied uniformly across every entity type and every
relationship endpoint) happens to produce exactly the id strings
(`CWE-1004`, `T1055.001`) that `data-preprocessing/CWE`/`mitre-attack`
already use for the same underlying concepts -- see above. Given the id
values are literally identical strings across datasets, there's nothing
for an `external_relationships.json` to express beyond that identity,
unlike CAPEC's `CAPEC-N`/CWE's `CWE-N`, genuinely different id spaces for
genuinely different entities referencing each other. So this preprocessor
does **not** produce an `external_relationships.json`.

Because D3FEND provides a distinct human-facing short code
(`d3f:d3fend-id`, e.g. `D3-AMED`) for `technique` records only, every
relationship in this dataset uses the stripped `@id` as `source_ref`/
`target_ref` throughout, not `d3fend-id`, so there's one consistent join
key across every type. `d3fend_id` is kept as an extra attribute on
`technique` records only, for citing D3FEND's own short code.

## What becomes a relationship

- `artifact.rdfs:hasSubClass` -> `has_subclass` edges (artifact -> child
  artifact). Verified to resolve 100% within `artifacts.json`.
- `weakness.rdfs:subClassOf` -> `child_of` edges (weakness -> parent
  weakness), the same relationship_type CWE's own preprocessor uses for
  the analogous edge. 10 of 1,113 parent refs point at the abstract root
  class `d3f:Weakness` itself rather than another weakness and are
  dropped, not emitted as edges to a non-entity.
- `weakness.d3f:weakness-of` / `d3f:may-be-weakness-of` -> `weakness_of` /
  `may_be_weakness_of` edges (weakness -> artifact). Both verified to
  resolve 100% into `artifacts.json`.
- `tactic.rdfs:subClassOf` is **dropped entirely, with no relationship
  emitted** -- every one of the 7 tactics points at the same abstract root
  class `d3f:DefensiveTactic`, not at another tactic; there is no real
  tactic-to-tactic hierarchy in this data.
- `mappings/latest.json` (14,003 flattened SPARQL-result rows, one per
  defense/offense trace) is mined for three kinds of edges, each
  deduplicated against the full row set rather than kept as 14,003 raw
  rows:
  - `technique --{def_artifact_rel_label}--> artifact` (166 unique edges,
    e.g. `analyzes`, `filters`, `isolates`) -- a fact not available
    anywhere else in this dataset (`techniques.json` alone carries no
    artifact relation).
  - `technique --enables--> tactic` (149 edges, one per technique --
    verified stable: every technique maps to exactly one tactic across
    every row it appears in).
  - `offensive-technique --{off_artifact_rel_label}--> artifact` (482
    unique edges, e.g. `modifies`, `may-modify`, `creates`) -- likewise
    D3FEND-only information layered onto the ATT&CK technique mirror.
  - `technique --counters--> offensive-technique` (3,544 unique edges) --
    the dataset's headline fact. Kept with `def_artifact`/
    `def_artifact_rel`/`off_artifact`/`off_artifact_rel` as edge
    attributes, since those explain *why* the technique counters that
    specific offensive technique (the same artifact, acted on by both
    sides, is the bridge). A `(technique, offensive-technique)` pair can
    legitimately have more than one such edge, if more than one
    artifact-bridge justifies the same pairing (3,544 edges cover 3,234
    distinct pairs).
  - `mapping`'s `off_tech_parent`/`off_tactic` and their `*_rel` fields are
    **not** turned into edges: they're the ATT&CK-side sub-technique and
    tactic facts, already fully captured by `data-preprocessing/mitre-attack`'s
    own `subtechnique-of` and `has_tactic` relationships -- re-deriving
    them here would just duplicate that dataset. `query_def_tech_label`/
    `top_def_tech_label` are dropped for a different reason: they carry no
    id at all (only a label), and were confirmed to be other rungs of the
    technique hierarchy that happened to anchor the SPARQL query that
    produced the row, not a fact about `def_tech` itself.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

DOMAIN_FILES: Dict[str, str] = {
    "technique": "techniques/latest.json",
    "tactic": "tactics/latest.json",
    "artifact": "artifacts/latest.json",
    "weakness": "weaknesses/latest.json",
    "mapping": "mappings/latest.json",
}

D3F_PREFIX = "d3f:"
ABSTRACT_WEAKNESS_ROOT = "Weakness"

HAS_SUBCLASS_RELATIONSHIP_TYPE = "has_subclass"
CHILD_OF_RELATIONSHIP_TYPE = "child_of"
WEAKNESS_OF_RELATIONSHIP_TYPE = "weakness_of"
MAY_BE_WEAKNESS_OF_RELATIONSHIP_TYPE = "may_be_weakness_of"
ENABLES_RELATIONSHIP_TYPE = "enables"
COUNTERS_RELATIONSHIP_TYPE = "counters"

OUTPUT_FILENAMES: Dict[str, str] = {
    "technique": "techniques.json",
    "tactic": "tactics.json",
    "artifact": "artifacts.json",
    "relationship": "relationships.json",
}


class ParseError(RuntimeError):
    pass


def load_domain(input_dir: Path, domain: str) -> List[Dict[str, Any]]:
    path = input_dir / DOMAIN_FILES[domain]
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    records = payload.get("records") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        raise ParseError(f"Expected {{'records': [...]}} at {path}")
    return [r for r in records if isinstance(r, dict)]


def strip_prefix(curie: Optional[str]) -> Optional[str]:
    if curie is None:
        return None
    return curie[len(D3F_PREFIX):] if curie.startswith(D3F_PREFIX) else curie


def ref_id(ref: Any) -> Optional[str]:
    if isinstance(ref, dict):
        return strip_prefix(ref.get("@id"))
    return None


def as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def literal_value(value: Any) -> Any:
    """Unwrap a JSON-LD typed literal ({"@type": "...", "@value": "3"}) to a plain value."""
    if isinstance(value, dict) and "@value" in value:
        return value["@value"]
    return value


def make_relationship(source_ref: str, target_ref: str, relationship_type: str, **extra: Any) -> Dict[str, Any]:
    seed_parts = [source_ref, relationship_type, target_ref]
    seed_parts.extend(f"{key}={extra[key]}" for key in sorted(extra))
    seed = "mitre-defend-preprocessing:" + "|".join(seed_parts)
    relationship_uuid = uuid.uuid5(uuid.NAMESPACE_URL, seed)
    record: Dict[str, Any] = {
        "id": f"relationship--{relationship_uuid}",
        "type": "relationship",
        "relationship_type": relationship_type,
        "source_ref": source_ref,
        "target_ref": target_ref,
    }
    record.update(extra)
    return record


# --------------------------------------------------------------------------
# Entity record builders
# --------------------------------------------------------------------------

DEFINITION_SEPARATOR = "\n\n"


def apply_aliases(record: Dict[str, Any], *sources: Any) -> None:
    """Merge D3FEND's alternate-name fields into one `aliases` list property.

    D3FEND splits alternate names across `d3f:synonym` and `skos:altLabel`; the 8
    artifacts carrying both have no value in common, so unioning them loses nothing.
    `aliases` is the name CWE/CAPEC/ATT&CK records use for the same concept -- these
    were the last of the four different spellings this project had for it.
    """
    merged: List[str] = []
    for source in sources:
        merged.extend(value for value in as_list(source) if value)
    if merged:
        record["aliases"] = list(dict.fromkeys(merged))


def build_technique_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    record: Dict[str, Any] = {
        "id": strip_prefix(raw["@id"]),
        "type": "technique",
        "name": raw.get("rdfs:label"),
    }
    if raw.get("d3f:d3fend-id"):
        record["d3fend_id"] = raw["d3f:d3fend-id"]
    apply_aliases(record, raw.get("d3f:synonym"))
    return record


def build_tactic_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    record: Dict[str, Any] = {
        "id": strip_prefix(raw["@id"]),
        "type": "tactic",
        "name": raw.get("rdfs:label"),
    }
    if raw.get("d3f:definition"):
        record["description"] = raw["d3f:definition"]
    if "d3f:display-order" in raw:
        record["display_order"] = int(literal_value(raw["d3f:display-order"]))
    if "d3f:display-priority" in raw:
        record["display_priority"] = int(literal_value(raw["d3f:display-priority"]))
    return record


def build_artifact_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    labels = as_list(raw.get("rdfs:label"))
    record: Dict[str, Any] = {
        "id": strip_prefix(raw["@id"]),
        "type": "artifact",
        "name": labels[0] if labels else None,
    }
    definitions = as_list(raw.get("d3f:definition"))
    if definitions:
        # 8 artifacts carry several genuinely different definitions (one per
        # industrial protocol); joined so `description` is a string everywhere it
        # appears rather than a string on most records and a list on 8.
        record["description"] = DEFINITION_SEPARATOR.join(definitions)
    apply_aliases(record, raw.get("d3f:synonym"), raw.get("skos:altLabel"))
    return record


# --------------------------------------------------------------------------
# Relationships from the five entity domains' own embedded ref fields
# --------------------------------------------------------------------------

def build_artifact_relationships(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    source_ref = strip_prefix(raw["@id"])
    return [
        make_relationship(source_ref, target_ref, HAS_SUBCLASS_RELATIONSHIP_TYPE)
        for target_ref in (ref_id(child) for child in as_list(raw.get("rdfs:hasSubClass")))
        if target_ref
    ]


def build_weakness_relationships(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    source_ref = strip_prefix(raw["@id"])
    relationships = []
    for parent in as_list(raw.get("rdfs:subClassOf")):
        target_ref = ref_id(parent)
        if target_ref and target_ref != ABSTRACT_WEAKNESS_ROOT:
            relationships.append(make_relationship(source_ref, target_ref, CHILD_OF_RELATIONSHIP_TYPE))
    for target in as_list(raw.get("d3f:weakness-of")):
        target_ref = ref_id(target)
        if target_ref:
            relationships.append(make_relationship(source_ref, target_ref, WEAKNESS_OF_RELATIONSHIP_TYPE))
    for target in as_list(raw.get("d3f:may-be-weakness-of")):
        target_ref = ref_id(target)
        if target_ref:
            relationships.append(make_relationship(source_ref, target_ref, MAY_BE_WEAKNESS_OF_RELATIONSHIP_TYPE))
    return relationships


# --------------------------------------------------------------------------
# Relationships mined from the flattened `mapping` export
# --------------------------------------------------------------------------

D3FEND_URI_PREFIX = "http://d3fend.mitre.org/ontologies/d3fend.owl#"


def mapping_value(row: Dict[str, Any], key: str) -> Optional[str]:
    cell = row.get(key)
    return cell.get("value") if isinstance(cell, dict) else cell


def mapping_ref(row: Dict[str, Any], key: str) -> Optional[str]:
    value = mapping_value(row, key)
    if value and value.startswith(D3FEND_URI_PREFIX):
        return value[len(D3FEND_URI_PREFIX):]
    return value


def relationship_type_from_label(label: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", label.strip().lower()).strip("_")


def build_mapping_relationships(mapping_rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    technique_artifact: Set[Tuple[str, str, str]] = set()
    technique_tactic: Set[Tuple[str, str]] = set()
    offensive_technique_artifact: Set[Tuple[str, str, str]] = set()
    counters: Set[Tuple[str, str, str, str, str, str]] = set()

    for row in mapping_rows:
        def_tech = mapping_ref(row, "def_tech")
        def_artifact = mapping_ref(row, "def_artifact")
        def_artifact_rel = mapping_value(row, "def_artifact_rel_label")
        def_tactic = mapping_ref(row, "def_tactic")
        off_tech = mapping_ref(row, "off_tech")
        off_artifact = mapping_ref(row, "off_artifact")
        off_artifact_rel = mapping_value(row, "off_artifact_rel_label")

        if def_tech and def_artifact and def_artifact_rel:
            technique_artifact.add((def_tech, def_artifact_rel, def_artifact))
        if def_tech and def_tactic:
            technique_tactic.add((def_tech, def_tactic))
        if off_tech and off_artifact and off_artifact_rel:
            offensive_technique_artifact.add((off_tech, off_artifact_rel, off_artifact))
        if def_tech and off_tech and def_artifact and def_artifact_rel and off_artifact and off_artifact_rel:
            counters.add((def_tech, off_tech, def_artifact, def_artifact_rel, off_artifact, off_artifact_rel))

    relationships: List[Dict[str, Any]] = []
    for source_ref, rel_label, target_ref in sorted(technique_artifact):
        relationships.append(make_relationship(source_ref, target_ref, relationship_type_from_label(rel_label)))
    for source_ref, target_ref in sorted(technique_tactic):
        relationships.append(make_relationship(source_ref, target_ref, ENABLES_RELATIONSHIP_TYPE))
    for source_ref, rel_label, target_ref in sorted(offensive_technique_artifact):
        relationships.append(make_relationship(source_ref, target_ref, relationship_type_from_label(rel_label)))
    for def_tech, off_tech, def_artifact, def_artifact_rel, off_artifact, off_artifact_rel in sorted(counters):
        relationships.append(
            make_relationship(
                def_tech,
                off_tech,
                COUNTERS_RELATIONSHIP_TYPE,
                def_artifact=def_artifact,
                def_artifact_rel=def_artifact_rel,
                off_artifact=off_artifact,
                off_artifact_rel=off_artifact_rel,
            )
        )
    return relationships


def parse(domains: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List[Dict[str, Any]]]:
    result: Dict[str, List[Dict[str, Any]]] = {
        "technique": [],
        "tactic": [],
        "artifact": [],
        "relationship": [],
    }

    for raw in domains["technique"]:
        result["technique"].append(build_technique_record(raw))
    for raw in domains["tactic"]:
        result["tactic"].append(build_tactic_record(raw))
    for raw in domains["artifact"]:
        result["artifact"].append(build_artifact_record(raw))
        result["relationship"].extend(build_artifact_relationships(raw))
    for raw in domains["weakness"]:
        result["relationship"].extend(build_weakness_relationships(raw))

    result["relationship"].extend(build_mapping_relationships(domains["mapping"]))

    print(
        "[mitre-defend-parser] parsed "
        f"{len(domains['technique'])} techniques, "
        f"{len(domains['tactic'])} tactics, "
        f"{len(domains['artifact'])} artifacts, "
        f"{len(domains['weakness'])} weaknesses (relationships only, no entity file), "
        f"{len(domains['mapping'])} mapping rows"
    )
    return result


def write_outputs(result: Dict[str, List[Dict[str, Any]]], output_dir: Path) -> Dict[str, int]:
    output_dir.mkdir(parents=True, exist_ok=True)
    counts: Dict[str, int] = {}
    for obj_type, records in result.items():
        filename = OUTPUT_FILENAMES[obj_type]
        path = output_dir / filename
        with path.open("w", encoding="utf-8") as handle:
            json.dump(records, handle, indent=2)
            handle.write("\n")
        counts[obj_type] = len(records)
    return counts


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    default_input = script_dir.parent.parent / "data-acquisition" / "mitre-defend"
    default_output_dir = script_dir

    parser = argparse.ArgumentParser(description="Trim D3FEND's JSON-LD domains down to a fixed field whitelist and extract relationships")
    parser.add_argument(
        "--input",
        default=str(default_input),
        help=f"Path to the D3FEND crawler's workspace directory (default: {default_input})",
    )
    parser.add_argument(
        "--output-dir",
        default=str(default_output_dir),
        help=f"Directory to write the trimmed entity/relationship files to (default: {default_output_dir})",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    input_dir = Path(args.input)
    output_dir = Path(args.output_dir)

    try:
        domains = {domain: load_domain(input_dir, domain) for domain in DOMAIN_FILES}
        result = parse(domains)
        counts = write_outputs(result, output_dir)
        print(
            "[mitre-defend-parser] wrote "
            f"{counts['technique']} techniques, "
            f"{counts['tactic']} tactics, "
            f"{counts['artifact']} artifacts, "
            f"{counts['relationship']} relationships "
            f"to {output_dir}"
        )
        return 0
    except (ParseError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
