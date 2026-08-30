"""CAPEC field-projection preprocessor. Full rationale in README.md.

Reads the CAPEC crawler's STIX 2.1 bundle (`data-acquisition/CAPEC/latest.json`)
and writes two files: `entities.json` (attack patterns and courses of action)
and `relationships.json` (every edge). Each record's own `type`
says which kind it is. `identity`/`marking-definition` are dropped as STIX
boilerplate.

Attack patterns are keyed `CAPEC-N` from their `capec` external_reference rather
than by STIX id (kept alongside as `stix_id`), and every relationship endpoint
naming one is rewritten to match. Their `cwe`/`ATTACK` external_references become
outward edges carrying `source_name`; the bibliographic ones are dropped.

Fields that don't survive verbatim: `x_capec_status`, `x_capec_execution_flow`
and `x_capec_skills_required` are dropped; `x_capec_alternate_terms` folds into
an `aliases` property; `x_capec_consequences` (a map, and nothing in the output
nests) flattens into `consequences`/`consequence_notes` lists on the attack
pattern -- a scope/impact pair is a label, not a thing to point at, and as 46
shared nodes it was a hub absorbing 1,563 edges from 368 patterns; the
attack-pattern ref fields become edges, keeping one direction of each
reciprocal pair (`child_of`, `can_precede`) and one edge per unordered `peer_of`
pair.

Every string is normalized on the way out by `clean_record()`: CRLF to LF,
non-breaking spaces and tabs to plain spaces, horizontal whitespace runs
collapsed, lines trimmed, empty values and duplicate list entries dropped.
`flatten_xhtml()` first renders the literal `<xhtml:p>`/`<xhtml:li>` markup CAPEC
leaves in its rich text to plain paragraphs and `"- "` lines, matching what CWE's
own flattener produces. Only the `xhtml:` namespace counts as markup -- every
other tag in those fields is quoted content and survives verbatim.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

ATTACK_PATTERN_FIELDS: Tuple[str, ...] = (
    "id",
    "name",
    "description",
    "type",
    "created",
    "modified",
    "x_capec_abstraction",
    "x_capec_domains",
    "x_capec_prerequisites",
    "x_capec_typical_severity",
    "x_capec_likelihood_of_attack",
    "x_capec_resources_required",
    "x_capec_example_instances",
    "x_capec_extended_description",
)

COURSE_OF_ACTION_FIELDS: Tuple[str, ...] = ("id", "name", "description", "type", "created", "modified")

RELATIONSHIP_FIELDS: Tuple[str, ...] = ("id", "type", "relationship_type", "source_ref", "target_ref", "created", "modified")

FIELDS_BY_TYPE: Dict[str, Tuple[str, ...]] = {
    "attack-pattern": ATTACK_PATTERN_FIELDS,
    "course-of-action": COURSE_OF_ACTION_FIELDS,
    "relationship": RELATIONSHIP_FIELDS,
}

DROPPED_TYPES = {"identity", "marking-definition"}

# external_references source_name values that become outward-pointing edges.
EXTERNAL_RELATIONSHIP_SOURCE_NAMES = {"cwe", "ATTACK"}
EXTERNAL_RELATIONSHIP_TYPE = "related_to"
EXTERNAL_RELATIONSHIP_KEY = "external-relationship"

# Only one direction of each reciprocal pair is kept; parent_of/can_follow are
# verified inverses, so storing them too would store every edge twice.
HIERARCHY_REF_FIELDS: Dict[str, str] = {
    "x_capec_child_of_refs": "child_of",
    "x_capec_can_precede_refs": "can_precede",
}

PEER_OF_RELATIONSHIP_TYPE = "peer_of"
ATTACK_PATTERN_RELATIONSHIP_KEY = "attack-pattern-relationship"

# Consequences read as `"Confidentiality: Read Data"`, and where CAPEC supplies the
# parenthetical explanation, `"Confidentiality: Read Data -- the attacker can ..."` --
# the same self-labelling shape CWE uses for its alias and introduction notes.
CONSEQUENCE_SEPARATOR = ": "
NOTE_SEPARATOR = " -- "

# CAPEC writes this scope with an underscore where CWE writes a space.
CONSEQUENCE_SCOPE_ALIASES: Dict[str, str] = {"Access_Control": "Access Control"}

# Renamed to the name another source already uses. The remaining `x_capec_*` fields
# (`prerequisites`, `typical_severity`, `domains`, ...) have no twin elsewhere, so they
# keep their prefix.
FIELD_NAME_OVERRIDES: Dict[str, str] = {
    "x_capec_extended_description": "extended_description",
    "x_capec_abstraction": "abstraction",  # CWE spells its own catalog-level field this way
}

# Upstream free text carries CRLF endings, non-breaking spaces, tabs and the indentation
# of the XML it was serialized from. None of it is content, all of it survives verbatim
# into the output and breaks string matching, so `clean_text()` normalizes it away.
COLLAPSIBLE_SPACE_PATTERN = re.compile(r"[\u00a0\u2007\u202f\ufeff\t]")
HORIZONTAL_RUN_PATTERN = re.compile(r"[^\S\n]{2,}")
BLANK_LINE_RUN_PATTERN = re.compile(r"\n{3,}")
SOFT_WRAP_PATTERN = re.compile(r"(?<!\n)\n(?!\n)")

# CAPEC wraps its rich text in XHTML tags that survive into the STIX bundle as literal
# markup (`<xhtml:p>...</xhtml:p>`). Only this `xhtml:` namespace is CAPEC's own
# formatting -- every other tag in these fields is quoted content (XSS payloads, SOAP
# envelopes, C includes, `<security-constraint>` samples) and must survive verbatim.
XHTML_BLOCK_TAG_PATTERN = re.compile(r"\s*(</?xhtml:(?:p|div|ul|ol|li|blockquote)\b[^>]*>)\s*", re.I)
XHTML_LIST_ITEM_PATTERN = re.compile(r"<xhtml:li\b[^>]*>", re.I)
XHTML_BLOCK_END_PATTERN = re.compile(r"</xhtml:(?:p|div|ul|ol|blockquote)>", re.I)
XHTML_TAG_PATTERN = re.compile(r"</?xhtml:[\w.-]+[^>]*>", re.I)

# Upstream writes a literal "None" where a field simply doesn't apply (11 attack
# patterns' `x_capec_prerequisites`). A missing field is omitted rather than written out,
# so this is dropped to match.
ABSENT_VALUE_SENTINELS = frozenset({"None"})

ENTITIES_FILENAME = "entities.json"
RELATIONSHIPS_FILENAME = "relationships.json"

# Which `parse()` result keys hold edges; the rest hold entities. Keys stay per-kind so
# the run summary can report a breakdown, but they no longer map to a file each.
RELATIONSHIP_KEYS: Tuple[str, ...] = (
    "relationship",
    EXTERNAL_RELATIONSHIP_KEY,
    ATTACK_PATTERN_RELATIONSHIP_KEY,
)


class ParseError(RuntimeError):
    pass


def load_objects(input_path: Path) -> List[Dict[str, Any]]:
    with input_path.open("r", encoding="utf-8") as handle:
        bundle = json.load(handle)
    objects = bundle.get("objects") if isinstance(bundle, dict) else None
    if not isinstance(objects, list):
        raise ParseError(f"Expected a STIX bundle with an 'objects' list at {input_path}")
    return [obj for obj in objects if isinstance(obj, dict)]


def clean_text(value: str, unwrap: bool = False) -> str:
    """Normalize one free-text string: CRLF/CR to LF, non-breaking and other exotic
    spaces plus tabs to a plain space, runs of horizontal whitespace collapsed, every
    line trimmed. Blank-line paragraph breaks are preserved; with `unwrap`, a lone
    newline is treated as source-indentation wrapping and becomes a space."""
    text = value.replace("\r\n", "\n").replace("\r", "\n")
    text = COLLAPSIBLE_SPACE_PATTERN.sub(" ", text)
    text = HORIZONTAL_RUN_PATTERN.sub(" ", text)
    text = "\n".join(line.strip() for line in text.split("\n"))
    if unwrap:
        text = SOFT_WRAP_PATTERN.sub(" ", text)
    return BLANK_LINE_RUN_PATTERN.sub("\n\n", text).strip()


def flatten_xhtml(value: str) -> str:
    """Render CAPEC's embedded XHTML markup to plain text, matching what CWE's own
    `flatten_xhtml()` produces: paragraphs separated by a blank line, list items as `"- "`
    lines. Whitespace hugging a *block* tag is the source document's indentation and goes;
    whitespace around an inline `<xhtml:b>`/`<xhtml:i>` is real spacing between words and
    stays. Tags outside the `xhtml:` namespace are quoted content, not markup, and are
    left exactly as they are -- as are newlines inside a paragraph, which in the 5 values
    that have any are line breaks in a quoted code sample."""
    text = XHTML_BLOCK_TAG_PATTERN.sub(r"\1", value)
    text = XHTML_LIST_ITEM_PATTERN.sub("\n- ", text)
    text = XHTML_BLOCK_END_PATTERN.sub("\n\n", text)
    text = XHTML_TAG_PATTERN.sub("", text)
    return clean_text(text)


def clean_value(value: Any) -> Any:
    """Flatten and normalize every string in a property value, dropping the ones left
    empty or equal to the `"None"` sentinel, and deduping list values."""
    if isinstance(value, str):
        text = flatten_xhtml(value)
        return None if not text or text in ABSENT_VALUE_SENTINELS else text
    if isinstance(value, list):
        kept = [item for item in map(clean_value, value) if item is not None]
        return list(dict.fromkeys(kept)) or None
    return value


def clean_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Run every property through `clean_value`, dropping those left empty. Applied once
    per record after the builders have run, so builders read source values verbatim."""
    cleaned: Dict[str, Any] = {}
    for key, value in record.items():
        value = clean_value(value)
        if value is not None:
            cleaned[key] = value
    return cleaned


def filter_object(obj: Dict[str, Any], fields: Tuple[str, ...]) -> Dict[str, Any]:
    return {field: obj[field] for field in fields if field in obj}


def extract_capec_id(obj: Dict[str, Any]) -> int:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "capec":
            external_id = str(ref.get("external_id") or "")
            return int(external_id.split("-", 1)[1])
    raise ParseError(f"attack-pattern {obj.get('id')} has no 'capec' external_reference")


def make_relationship(source_ref: str, target_ref: str, relationship_type: str, **extra: Any) -> Dict[str, Any]:
    seed = f"capec-preprocessing:{source_ref}|{relationship_type}|{target_ref}"
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


def build_external_relationships(obj: Dict[str, Any], capec_id: int) -> List[Dict[str, Any]]:
    source_ref = f"CAPEC-{capec_id}"
    relationships = []
    seen = set()
    for ref in obj.get("external_references", []):
        source_name = ref.get("source_name")
        target_ref = ref.get("external_id")
        if source_name not in EXTERNAL_RELATIONSHIP_SOURCE_NAMES or not target_ref:
            continue
        if (source_name, target_ref) in seen:
            continue  # 3 attack patterns list the same external reference twice upstream
        seen.add((source_name, target_ref))
        relationships.append(make_relationship(source_ref, target_ref, EXTERNAL_RELATIONSHIP_TYPE, source_name=source_name))
    return relationships


def normalize_relationship_type(relationship_type: str) -> str:
    """STIX spells its own relationship types with hyphens, while every type derived here
    is snake_case, so native types are rewritten to match. (CAPEC's only native type is
    `mitigates`; this guards the passthrough against upstream adding a hyphenated one.)"""
    return relationship_type.replace("-", "_")


def resolve_capec_ref(stix_id: str, id_to_capec_id: Dict[str, int]) -> str:
    capec_id = id_to_capec_id.get(stix_id)
    if capec_id is None:
        raise ParseError(f"attack-pattern ref {stix_id!r} does not resolve to any known attack-pattern")
    return f"CAPEC-{capec_id}"


def remap_attack_pattern_ref(ref: str, id_to_capec_id: Dict[str, int]) -> str:
    """Rewrite a relationship endpoint from an attack-pattern's STIX id to its CAPEC-N
    id. Endpoints that aren't one (e.g. a course-of-action) pass through unchanged."""
    capec_id = id_to_capec_id.get(ref)
    return f"CAPEC-{capec_id}" if capec_id is not None else ref


def build_hierarchy_relationships(obj: Dict[str, Any], capec_id: int, id_to_capec_id: Dict[str, int]) -> List[Dict[str, Any]]:
    source_ref = f"CAPEC-{capec_id}"
    relationships = []
    for ref_field, relationship_type in HIERARCHY_REF_FIELDS.items():
        for target_stix_id in obj.get(ref_field, []):
            target_ref = resolve_capec_ref(target_stix_id, id_to_capec_id)
            relationships.append(make_relationship(source_ref, target_ref, relationship_type))
    return relationships


def apply_alternate_terms(obj: Dict[str, Any], record: Dict[str, Any]) -> None:
    """Fold `x_capec_alternate_terms` into an `aliases` list -- the name CWE/ATT&CK/
    D3FEND records use too. As edges these pointed at the alias text itself, which is
    no entity, so loading them would have invented a phantom node per alias string."""
    aliases = [alias for alias in obj.get("x_capec_alternate_terms", []) or [] if alias]
    if aliases:
        record["aliases"] = list(dict.fromkeys(aliases))


def split_impact(value: str) -> Tuple[str, Optional[str]]:
    """Split CAPEC's impact string into its short code and its trailing parenthetical
    note -- "Execute Unauthorized Commands (The attacker may ...)". That collapses 134
    distinct strings to the 10 real impact codes (4 shared verbatim with CWE) and puts
    the explanation on the edge, where CWE already keeps its consequence `note`.
    Verified unambiguous: no impact code contains a parenthesis, and every
    parenthetical closes at end of string."""
    index = value.find(" (")
    if index < 0 or not value.rstrip().endswith(")"):
        return value, None
    return value[:index], value[index + 2:].rstrip()[:-1]


def apply_consequences(obj: Dict[str, Any], record: Dict[str, Any]) -> None:
    """Fold `x_capec_consequences` (a scope -> impact-list map) into
    `consequences`/`consequence_notes` properties, the same treatment `aliases` gets.
    As nodes these were 46 (scope, impact) pairs holding nothing but the pair itself,
    and they absorbed 1,563 edges from 368 attack patterns: `Confidentiality: Read Data`
    is a label on an attack pattern, not a thing it points at, and as a node it was a hub
    every traversal then had to route around. The 394 parenthetical explanations keep
    their pairing as `"scope: impact -- note"` strings, which also survives one pattern
    giving the same pair two different notes."""
    consequences, notes = [], []
    for raw_scope, impacts in (obj.get("x_capec_consequences") or {}).items():
        scope = CONSEQUENCE_SCOPE_ALIASES.get(raw_scope, raw_scope)
        for raw_impact in impacts:
            impact, note = split_impact(raw_impact)
            label = f"{scope}{CONSEQUENCE_SEPARATOR}{impact}"
            consequences.append(label)
            if note:
                notes.append(f"{label}{NOTE_SEPARATOR}{note}")
    if consequences:
        record["consequences"] = list(dict.fromkeys(consequences))
    if notes:
        record["consequence_notes"] = list(dict.fromkeys(notes))


def build_peer_relationships(attack_patterns: Sequence[Dict[str, Any]], id_to_capec_id: Dict[str, int]) -> List[Dict[str, Any]]:
    """peer_of is symmetric but not consistently reciprocal upstream, so dedupe to one
    edge per unordered pair (canonical direction: lower capec_id -> higher)."""
    seen_pairs = set()
    relationships = []
    for obj in attack_patterns:
        capec_id = id_to_capec_id[obj["id"]]
        for peer_stix_id in obj.get("x_capec_peer_of_refs", []):
            peer_capec_id = id_to_capec_id.get(peer_stix_id)
            if peer_capec_id is None:
                raise ParseError(f"attack-pattern ref {peer_stix_id!r} does not resolve to any known attack-pattern")
            pair = (min(capec_id, peer_capec_id), max(capec_id, peer_capec_id))
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            relationships.append(make_relationship(f"CAPEC-{pair[0]}", f"CAPEC-{pair[1]}", PEER_OF_RELATIONSHIP_TYPE))
    return relationships


def build_attack_pattern_record(obj: Dict[str, Any], capec_id: int) -> Dict[str, Any]:
    record: Dict[str, Any] = {}
    for field in ATTACK_PATTERN_FIELDS:
        if field == "id":
            record["id"] = f"CAPEC-{capec_id}"
            record["stix_id"] = obj["id"]
        elif field in obj:
            record[FIELD_NAME_OVERRIDES.get(field, field)] = obj[field]
    apply_alternate_terms(obj, record)
    apply_consequences(obj, record)
    return record


def parse(objects: Sequence[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    attack_patterns = [obj for obj in objects if str(obj.get("type") or "") == "attack-pattern"]
    id_to_capec_id = {obj["id"]: extract_capec_id(obj) for obj in attack_patterns}

    result: Dict[str, List[Dict[str, Any]]] = {obj_type: [] for obj_type in FIELDS_BY_TYPE}
    result[EXTERNAL_RELATIONSHIP_KEY] = []
    result[ATTACK_PATTERN_RELATIONSHIP_KEY] = build_peer_relationships(attack_patterns, id_to_capec_id)
    dropped_counts: Dict[str, int] = {}

    for obj in objects:
        obj_type = str(obj.get("type") or "")
        if obj_type == "attack-pattern":
            capec_id = id_to_capec_id[obj["id"]]
            result["attack-pattern"].append(build_attack_pattern_record(obj, capec_id))
            result[EXTERNAL_RELATIONSHIP_KEY].extend(build_external_relationships(obj, capec_id))
            result[ATTACK_PATTERN_RELATIONSHIP_KEY].extend(build_hierarchy_relationships(obj, capec_id, id_to_capec_id))
            continue
        if obj_type == "relationship":
            record = filter_object(obj, RELATIONSHIP_FIELDS)
            record["relationship_type"] = normalize_relationship_type(record["relationship_type"])
            record["source_ref"] = remap_attack_pattern_ref(record["source_ref"], id_to_capec_id)
            record["target_ref"] = remap_attack_pattern_ref(record["target_ref"], id_to_capec_id)
            result["relationship"].append(record)
            continue
        fields = FIELDS_BY_TYPE.get(obj_type)
        if fields is not None:
            result[obj_type].append(filter_object(obj, fields))
            continue
        if obj_type not in DROPPED_TYPES:
            print(f"[capec-parser] warning: skipping unexpected object type '{obj_type}'", file=sys.stderr)
        dropped_counts[obj_type] = dropped_counts.get(obj_type, 0) + 1

    dropped_summary = ", ".join(f"{count} {obj_type}" for obj_type, count in sorted(dropped_counts.items()))
    print(f"[capec-parser] parsed {len(objects)} objects; dropped {dropped_summary or 'nothing'}")
    return result


def write_outputs(result: Dict[str, List[Dict[str, Any]]], output_dir: Path) -> Dict[str, int]:
    """Write every entity record to entities.json and every edge to relationships.json,
    concatenated in `result`'s own insertion order so reruns are byte-stable. Every
    record passes through `clean_record()` on the way out -- one place, so no builder has
    to remember to flatten markup or trim whitespace itself."""
    output_dir.mkdir(parents=True, exist_ok=True)
    files: Dict[str, List[Dict[str, Any]]] = {ENTITIES_FILENAME: [], RELATIONSHIPS_FILENAME: []}
    for key, records in result.items():
        target = RELATIONSHIPS_FILENAME if key in RELATIONSHIP_KEYS else ENTITIES_FILENAME
        files[target].extend(clean_record(record) for record in records)
    for filename, records in files.items():
        with (output_dir / filename).open("w", encoding="utf-8") as handle:
            json.dump(records, handle, indent=2)
            handle.write("\n")
    return {key: len(records) for key, records in result.items()}


def format_counts(counts: Dict[str, int], keys: Sequence[str]) -> str:
    """Total plus per-kind breakdown: `1538 (559 attack-pattern, 552 course-of-action, ...)`."""
    breakdown = ", ".join(f"{counts[key]} {key}" for key in keys if counts[key])
    return f"{sum(counts[key] for key in keys)} ({breakdown})"


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    default_input = script_dir.parent.parent / "data-acquisition" / "CAPEC" / "latest.json"

    parser = argparse.ArgumentParser(description="Trim CAPEC's STIX bundle down to a fixed field whitelist per object type")
    parser.add_argument("--input", default=str(default_input), help=f"Path to CAPEC's latest.json (default: {default_input})")
    parser.add_argument("--output-dir", default=str(script_dir), help=f"Directory to write entities.json / relationships.json (default: {script_dir})")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    output_dir = Path(args.output_dir)

    try:
        result = parse(load_objects(Path(args.input)))
        counts = write_outputs(result, output_dir)
        entity_keys = [key for key in counts if key not in RELATIONSHIP_KEYS]
        relationship_keys = [key for key in counts if key in RELATIONSHIP_KEYS]
        print(
            f"[capec-parser] wrote {format_counts(counts, entity_keys)} entities to {ENTITIES_FILENAME} "
            f"and {format_counts(counts, relationship_keys)} relationships to {RELATIONSHIPS_FILENAME}, in {output_dir}"
        )
        return 0
    except (ParseError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
