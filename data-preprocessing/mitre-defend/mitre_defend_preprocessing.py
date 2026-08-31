"""MITRE D3FEND field-projection preprocessor. Full rationale in README.md.

Reads six raw JSON files from the D3FEND crawler
(`data-acquisition/mitre-defend/{techniques,tactics,artifacts,weaknesses,
mappings,ontology}/latest.json`) and writes two files: `entities.json` (the
`technique`/`tactic`/`artifact` records, distinguished by their own `type`) and
`relationships.json` (every edge). `weaknesses/latest.json` is read for its
embedded edges only, and `offensive-techniques/latest.json` isn't read at all:
both are mirrors of another source here (CWE weaknesses, ATT&CK techniques) and
were checked before dropping -- all 943 weakness ids and all 835
offensive-technique ids exist in `CWE`/`mitre-attack`, and D3FEND's definitions
were either a truncated prefix of ATT&CK's or identical to CWE's on 97.7% of
records. Those endpoints join by bare id against the other source's
`entities.json`.

D3FEND's own JSON is JSON-LD, not STIX: every record is keyed by an `@id` like
`"d3f:CWE-1004"`, and most field names carry an `rdfs:`/`d3f:`/`owl:`/`skos:`
prefix. Those raw keys contain a literal colon, awkward in a flattened output, so
unlike CWE/CAPEC/ATT&CK every field here is renamed to plain snake_case, unified
with the rest of the project (`d3f:definition` -> `description`; `d3f:synonym`
plus `skos:altLabel` merged into `aliases`). JSON-LD also collapses a
cardinality-1 value to a bare scalar (`as_list()` normalizes) and wraps typed
literals as `{"@type": ..., "@value": ...}` (`literal_value()` unwraps).
`_content_hash`/`_first_seen_at` (this project's own crawler bookkeeping) and
`@type` (OWL class-membership boilerplate) are dropped from every record.

No edge here carries a `source_name`. Stripping the `d3f:` prefix from every
`@id` produces exactly the id strings (`CWE-1004`, `T1055.001`) that CWE and
ATT&CK already use for the same concepts, so a dedicated external edge would
express nothing beyond that identity -- unlike CAPEC's and CWE's genuinely
different id spaces. Every endpoint uses the stripped `@id` rather than D3FEND's
short code (`d3f:d3fend-id`, e.g. `D3-AMED`), which exists for `technique`
records only and is kept there as a `d3fend_id` attribute.

Edges come from the entity domains' own ref fields (`rdfs:hasSubClass` and the two
`weakness-of` forms -- weaknesses' `rdfs:subClassOf` is dropped as a duplicate of
CWE's own hierarchy, see `build_weakness_relationships`) and from mining
`mappings/latest.json`'s 14,003 SPARQL-result rows, deduplicated against the full
row set, for `technique --{relation}--> artifact`, `technique --enables--> tactic`,
`offensive-technique --{relation}--> artifact`, and the dataset's headline fact,
`technique --counters--> offensive-technique`.

The artifact relations are bucketed rather than kept one type per name: D3FEND's
70 relation names produced 67 `relationship_type` values here, 61 of them sharing
648 edges. See `ARTIFACT_RELATION_BUCKETS` below for why, and README.md for the
bucket table. The original name survives on every such edge as `verb`, so the
reduction is lossless.

Every string is normalized on the way out by `clean_record()`: CRLF to LF,
non-breaking spaces and tabs to plain spaces, horizontal whitespace runs
collapsed, lines trimmed, empty values and duplicate list entries dropped.
Blank-line paragraph breaks survive; source-document indentation does not.
Markup that is quoted content (payloads, code samples) is left verbatim.
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
    "ontology": "ontology/latest.json",
}

D3F_PREFIX = "d3f:"
D3FEND_URI_PREFIX = "http://d3fend.mitre.org/ontologies/d3fend.owl#"

# The 7 tactics' `rdfs:subClassOf` is dropped: all 7 point at the abstract root class
# `d3f:DefensiveTactic`, so there is no real tactic-to-tactic hierarchy to emit.
CHILD_OF_RELATIONSHIP_TYPE = "child_of"  # same relationship_type CWE uses for its analogous edge
WEAKNESS_OF_RELATIONSHIP_TYPE = "weakness_of"
ENABLES_RELATIONSHIP_TYPE = "enables"
COUNTERS_RELATIONSHIP_TYPE = "counters"

# ---------------------------------------------------------------------------
# Relation vocabulary
# ---------------------------------------------------------------------------
# D3FEND names 70 distinct artifact relations across its two sides, and turning each
# into its own `relationship_type` produced 67 types here -- 61 of which covered 648
# edges between them, several with a single edge. That is a schema too large to put in
# a retrieval prompt and too sparse to query: a relation with one edge cannot support
# an answer. It also misreads the source. In D3FEND's own ontology these are *properties*
# (`d3f:analyzes`, `d3f:monitors`), not classes, and the `counters` rows already carry
# them as attributes -- so promoting them to types was never what the catalog meant.
#
# Each relation is therefore mapped to one of eight buckets, and the original verb is
# kept on the edge as `verb`. Nothing is lost: `verb` recovers the exact original type,
# while `relationship_type` is now coarse enough to traverse and name in a prompt.
#
# Buckets are per-side because the same verb means opposite things depending on who
# performs it. An attack that deletes a log is destroying evidence; a defence that
# deletes a file is evicting a threat. The side is known exactly -- these come from
# different columns of the mappings export -- so it is never inferred.
DEFENSIVE_SIDE = "defensive"
OFFENSIVE_SIDE = "offensive"

# D3FEND hedges a relation by prefixing `may-`. That is a confidence, not a different
# relation, so it becomes `certainty` and the verb keeps its asserted spelling. Listed
# explicitly rather than stripped, because stripping `may-modify` yields `modify`, which
# is not the asserted form (`modifies`).
HEDGED_RELATION_LABELS: Dict[str, str] = {
    "may-access": "accesses",
    "may-add": "adds",
    "may-contain": "contains",
    "may-create": "creates",
    "may-execute": "executes",
    "may-invoke": "invokes",
    "may-modify": "modifies",
    "may-produce": "produces",
    "may-run": "runs",
    "may-transfer": "transfers",
}

CERTAINTY_ASSERTED = "asserted"
CERTAINTY_POSSIBLE = "possible"

ARTIFACT_RELATION_BUCKETS: Dict[str, Dict[str, str]] = {
    OFFENSIVE_SIDE: {
        # reaching or reading an artifact without changing it
        "accesses": "accesses", "reads": "accesses", "enumerates": "accesses",
        "queries": "accesses", "interprets": "accesses", "uses": "accesses",
        "connects": "accesses",
        # bringing an artifact into being, or placing one
        "produces": "creates", "creates": "creates", "adds": "creates",
        "copies": "creates", "loads": "creates", "installs": "creates",
        # changing, damaging or falsifying one that already exists
        "modifies": "modifies", "transfers": "modifies", "deletes": "modifies",
        "disables": "modifies", "abuses": "modifies", "obfuscates": "modifies",
        "encrypts": "modifies", "forges": "modifies", "unmounts": "modifies",
        "injects": "modifies",
        # causing one to run
        "executes": "executes", "invokes": "executes", "runs": "executes",
    },
    DEFENSIVE_SIDE: {
        # looking at an artifact to learn from it
        "analyzes": "observes", "monitors": "observes", "inventories": "observes",
        "maps": "observes", "evaluates": "observes", "verifies": "observes",
        "validates": "observes", "authenticates": "observes", "uses": "observes",
        "reads": "observes", "accesses": "observes",
        # stopping or limiting what can be done with it
        "filters": "constrains", "blocks": "constrains", "isolates": "constrains",
        "restricts": "constrains", "quarantines": "constrains", "terminates": "constrains",
        "suspends": "constrains", "use-limits": "constrains", "neutralizes": "constrains",
        "contains": "constrains", "disables": "constrains",
        # changing it so it resists attack, deception included
        "hardens": "hardens", "strengthens": "hardens", "encrypts": "hardens",
        "configures": "hardens", "updates": "hardens", "regenerates": "hardens",
        "manages": "hardens", "creates": "hardens", "modifies": "hardens",
        "spoofs": "hardens", "obfuscates": "hardens",
        # removing it or putting it back as it was
        "restores": "restores", "erases": "restores", "deletes": "restores",
    },
}

WEAKNESS_REF_FIELDS: Tuple[Tuple[str, str], ...] = (
    ("d3f:weakness-of", CERTAINTY_ASSERTED),
    ("d3f:may-be-weakness-of", CERTAINTY_POSSIBLE),
)

DEFINITION_SEPARATOR = "\n\n"

# Upstream free text carries CRLF endings, non-breaking spaces, tabs and the indentation
# of the document it was serialized from. None of it is content, all of it survives
# verbatim into the output and breaks string matching, so `clean_text()` normalizes it away.
COLLAPSIBLE_SPACE_PATTERN = re.compile(r"[\u00a0\u2007\u202f\ufeff\t]")
HORIZONTAL_RUN_PATTERN = re.compile(r"[^\S\n]{2,}")
BLANK_LINE_RUN_PATTERN = re.compile(r"\n{3,}")
SOFT_WRAP_PATTERN = re.compile(r"(?<!\n)\n(?!\n)")

# D3FEND has no absent-value marker string of its own; an unset field is simply missing.
ABSENT_VALUE_SENTINELS: frozenset = frozenset()

ENTITIES_FILENAME = "entities.json"
RELATIONSHIPS_FILENAME = "relationships.json"

# Which `parse()` result keys hold edges; the rest hold entities. Keys stay per-kind so
# the run summary can report a breakdown, but they no longer map to a file each.
RELATIONSHIP_KEYS: Tuple[str, ...] = ("relationship",)


class ParseError(RuntimeError):
    pass


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


def clean_value(value: Any) -> Any:
    """Normalize every string in a property value, dropping the ones left empty or equal
    to a sentinel, and deduping list values."""
    if isinstance(value, str):
        text = clean_text(value)
        return None if not text or text in ABSENT_VALUE_SENTINELS else text
    if isinstance(value, list):
        kept = [item for item in map(clean_value, value) if item is not None]
        return list(dict.fromkeys(kept)) or None
    return value


def read_collected_at(manifest_path: Path) -> str | None:
    """When the acquisition layer last fetched this source, read from its manifest.

    Deliberately the *crawl* time and not this run's wall clock. Stamping records with
    the moment preprocessing happened to run would make every rerun differ, and
    byte-identical reruns are what lets a checksum tell "the source changed" apart from
    "I ran it again". This value only moves when the crawler actually refetched."""
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        print(f"[mitre-defend-parser] warning: no readable manifest at {manifest_path}; records get no collected_at", file=sys.stderr)
        return None
    collected_at = manifest.get("last_successful_fetch") or manifest.get("generated_at")
    if not collected_at:
        print(f"[mitre-defend-parser] warning: {manifest_path.name} has no fetch timestamp; records get no collected_at", file=sys.stderr)
    return collected_at


def stamp_collected_at(record: Dict[str, Any], collected_at: str | None) -> Dict[str, Any]:
    """Add the source's crawl time to a finished record. Applied last -- after
    `clean_record()` and any relationship collapse -- so field order stays stable and the
    value is never mistaken for a source field that differs across merged records."""
    if collected_at:
        record["collected_at"] = collected_at
    return record


def clean_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Run every property through `clean_value`, dropping those left empty. Applied once
    per record on the way out, so no builder has to remember to trim or dedupe itself."""
    cleaned: Dict[str, Any] = {}
    for key, value in record.items():
        value = clean_value(value)
        if value is not None:
            cleaned[key] = value
    return cleaned


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
    return strip_prefix(ref.get("@id")) if isinstance(ref, dict) else None


def as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def literal_value(value: Any) -> Any:
    """Unwrap a JSON-LD typed literal ({"@type": "...", "@value": "3"}) to a plain value."""
    return value["@value"] if isinstance(value, dict) and "@value" in value else value


def make_relationship(source_ref: str, target_ref: str, relationship_type: str, **extra: Any) -> Dict[str, Any]:
    # Seeded on the triple alone: `collapse_parallel_relationships()` leaves exactly one
    # record per (source, type, target), so there is nothing left for `extra` to
    # disambiguate, and an id that ignores attributes stays put when they change.
    seed_parts = [source_ref, relationship_type, target_ref]
    relationship_uuid = uuid.uuid5(uuid.NAMESPACE_URL, "mitre-defend-preprocessing:" + "|".join(seed_parts))
    record: Dict[str, Any] = {
        "id": f"relationship--{relationship_uuid}",
        "type": "relationship",
        "relationship_type": relationship_type,
        "source_ref": source_ref,
        "target_ref": target_ref,
    }
    record.update(extra)
    return record


def apply_aliases(record: Dict[str, Any], *sources: Any) -> None:
    """Merge D3FEND's `d3f:synonym`/`skos:altLabel` into one `aliases` list -- the name
    CWE/CAPEC/ATT&CK use for the same concept. The 8 artifacts carrying both have no
    value in common, so unioning them loses nothing."""
    merged: List[str] = []
    for source in sources:
        merged.extend(value for value in as_list(source) if value)
    if merged:
        record["aliases"] = list(dict.fromkeys(merged))


def index_ontology(records: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """`ontology/latest.json` keyed by the same stripped `@id` the entity records use.

    It covers the whole published ontology (7,672 nodes), most of which is ATT&CK classes
    and OWL boilerplate this project takes nothing from; only ids that match an entity
    built here are ever read out of it.
    """
    return {stripped: raw for raw in records if (stripped := strip_prefix(raw.get("@id")))}


def apply_ontology_text(record: Dict[str, Any], ontology: Dict[str, Dict[str, Any]]) -> None:
    """Fill `description`/`kb_article` from the ontology.

    The `/api/*` endpoints the other domains come from return identity fields only, so
    without this 1,178 of 1,193 records reach the graph with no prose at all -- unusable
    as embedding or keyword-search targets, which silently removes the whole defensive
    catalog from retrieval. The ontology carries `d3f:definition` for 271/271 techniques,
    7/7 tactics and 867/915 artifacts, and the long-form `d3f:kb-article` for 193.

    An endpoint definition wins where one exists, so this only ever fills a gap: the two
    sources never disagree (0 endpoint-only values, and the 7 tactic definitions are
    byte-identical in both), except on the 8 multi-definition industrial-protocol
    artifacts, where the endpoint's several definitions are the fuller answer and the
    ontology's single one would lose the rest.
    """
    raw = ontology.get(record["id"])
    if not raw:
        return
    if not record.get("description"):
        definitions = as_list(raw.get("d3f:definition"))
        if definitions:
            record["description"] = DEFINITION_SEPARATOR.join(definitions)
    kb_article = as_list(raw.get("d3f:kb-article"))
    if kb_article:
        record["kb_article"] = DEFINITION_SEPARATOR.join(kb_article)


def build_technique_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    record: Dict[str, Any] = {"id": strip_prefix(raw["@id"]), "type": "technique", "name": raw.get("rdfs:label")}
    if raw.get("d3f:d3fend-id"):
        record["d3fend_id"] = raw["d3f:d3fend-id"]
    apply_aliases(record, raw.get("d3f:synonym"))
    return record


def build_tactic_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    record: Dict[str, Any] = {"id": strip_prefix(raw["@id"]), "type": "tactic", "name": raw.get("rdfs:label")}
    if raw.get("d3f:definition"):
        record["description"] = raw["d3f:definition"]
    for source_field, out_field in (("d3f:display-order", "display_order"), ("d3f:display-priority", "display_priority")):
        if source_field in raw:
            record[out_field] = int(literal_value(raw[source_field]))
    return record


def build_artifact_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    labels = as_list(raw.get("rdfs:label"))
    record: Dict[str, Any] = {"id": strip_prefix(raw["@id"]), "type": "artifact", "name": labels[0] if labels else None}
    definitions = as_list(raw.get("d3f:definition"))
    if definitions:
        # 8 artifacts carry several genuinely different definitions (one per industrial
        # protocol); joined so `description` is a string everywhere rather than a list on 8
        record["description"] = DEFINITION_SEPARATOR.join(definitions)
    apply_aliases(record, raw.get("d3f:synonym"), raw.get("skos:altLabel"))
    return record


def build_artifact_relationships(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    """`rdfs:hasSubClass` -> artifact -> child artifact. Resolves 100% within this
    dataset's own artifacts.

    Emitted reversed, as `child_of`, so both hierarchies in this file point the same way
    -- specific to general -- and match the name CWE and CAPEC already use. D3FEND is the
    only source that states its taxonomy downwards; keeping that direction meant a reader
    had to know which catalog an edge came from before it could tell parent from child.
    """
    parent_ref = strip_prefix(raw["@id"])
    return [
        make_relationship(child_ref, parent_ref, CHILD_OF_RELATIONSHIP_TYPE)
        for child_ref in (ref_id(child) for child in as_list(raw.get("rdfs:hasSubClass")))
        if child_ref
    ]


def build_weakness_relationships(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The two `weakness-of` fields pointing at artifacts (both resolve 100% into this
    dataset's artifacts).

    `rdfs:subClassOf` is deliberately not read. It restates the CWE hierarchy, which the
    CWE module already loads from CWE's own `RelatedWeaknesses`: of the 1,103 `CWE-N ->
    CWE-N` links it produced, 1,079 were byte-identical to CWE's and the remaining 24
    contradicted rather than extended it -- D3FEND has CWE-1051 under CWE-665 where CWE
    itself has CWE-1419, and CWE-1265 under CWE-691 where CWE has CWE-662, the shape of a
    stale copy of an older CWE tree. Keeping it stored every CWE parent link twice and
    gave the graph two disagreeing answers for 24 of them. The artifact hierarchy
    (`build_artifact_relationships`) is D3FEND's own and stays.
    """
    source_ref = strip_prefix(raw["@id"])
    relationships = []
    for source_field, certainty in WEAKNESS_REF_FIELDS:
        for target in as_list(raw.get(source_field)):
            target_ref = ref_id(target)
            if target_ref:
                # `may-be-weakness-of` is the same relation hedged, so it folds into
                # `weakness_of` with the hedge carried as `certainty`, exactly as the
                # artifact relations do.
                relationships.append(
                    make_relationship(source_ref, target_ref, WEAKNESS_OF_RELATIONSHIP_TYPE, certainty=certainty)
                )
    return relationships


def mapping_value(row: Dict[str, Any], key: str) -> Optional[str]:
    cell = row.get(key)
    return cell.get("value") if isinstance(cell, dict) else cell


def mapping_ref(row: Dict[str, Any], key: str) -> Optional[str]:
    value = mapping_value(row, key)
    if value and value.startswith(D3FEND_URI_PREFIX):
        return value[len(D3FEND_URI_PREFIX):]
    return value


def snake_case_label(label: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", label.strip().lower()).strip("_")


def resolve_artifact_relation(label: str, side: str) -> Tuple[str, str, str]:
    """Map one raw relation label to (relationship_type, verb, certainty).

    Raises rather than guessing: a D3FEND release that adds a relation must fail the
    run loudly here, not arrive silently in the output as an unmapped 68th type.
    """
    normalized = label.strip().lower()
    certainty = CERTAINTY_ASSERTED
    if normalized in HEDGED_RELATION_LABELS:
        normalized = HEDGED_RELATION_LABELS[normalized]
        certainty = CERTAINTY_POSSIBLE
    bucket = ARTIFACT_RELATION_BUCKETS[side].get(normalized)
    if bucket is None:
        raise ParseError(f"unmapped D3FEND {side} relation {label!r} -- add it to ARTIFACT_RELATION_BUCKETS")
    return bucket, snake_case_label(normalized), certainty


def build_mapping_relationships(mapping_rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Mine the flattened SPARQL export for four kinds of edge, deduplicated across all
    rows. `counters` keeps the four artifact-bridge fields as edge attributes because
    they explain *why* the technique counters that offensive technique -- so one
    (technique, offensive-technique) pair can legitimately carry more than one edge.
    `off_tech_parent`/`off_tactic` are skipped: mitre-attack already emits those facts.
    `query_def_tech_label`/`top_def_tech_label` are skipped too -- they carry no id, and
    name other rungs of the technique hierarchy that anchored the query, not `def_tech`."""
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
        bucket, verb, certainty = resolve_artifact_relation(rel_label, DEFENSIVE_SIDE)
        relationships.append(make_relationship(source_ref, target_ref, bucket, verb=verb, certainty=certainty))
    for source_ref, target_ref in sorted(technique_tactic):
        relationships.append(make_relationship(source_ref, target_ref, ENABLES_RELATIONSHIP_TYPE))
    for source_ref, rel_label, target_ref in sorted(offensive_technique_artifact):
        bucket, verb, certainty = resolve_artifact_relation(rel_label, OFFENSIVE_SIDE)
        relationships.append(make_relationship(source_ref, target_ref, bucket, verb=verb, certainty=certainty))
    for def_tech, off_tech, def_artifact, def_artifact_rel, off_artifact, off_artifact_rel in sorted(counters):
        # The bridge attributes name the same relations, so they get the same treatment:
        # one spelling, the hedge as a certainty. Raw D3FEND writes these with a hyphen
        # (`may-modify`) and the standalone edges with an underscore (`may_modify`), so
        # without this the identical fact was spelled two ways in one file.
        def_bucket, def_verb, def_certainty = resolve_artifact_relation(def_artifact_rel, DEFENSIVE_SIDE)
        off_bucket, off_verb, off_certainty = resolve_artifact_relation(off_artifact_rel, OFFENSIVE_SIDE)
        relationships.append(
            make_relationship(
                def_tech,
                off_tech,
                COUNTERS_RELATIONSHIP_TYPE,
                def_artifact=def_artifact,
                def_artifact_rel=def_bucket,
                def_artifact_verb=def_verb,
                def_artifact_certainty=def_certainty,
                off_artifact=off_artifact,
                off_artifact_rel=off_bucket,
                off_artifact_verb=off_verb,
                off_artifact_certainty=off_certainty,
            )
        )
    return relationships


def parse(domains: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List[Dict[str, Any]]]:
    result: Dict[str, List[Dict[str, Any]]] = {"technique": [], "tactic": [], "artifact": [], "relationship": []}

    ontology = index_ontology(domains["ontology"])

    for raw in domains["technique"]:
        result["technique"].append(build_technique_record(raw))
    for raw in domains["tactic"]:
        result["tactic"].append(build_tactic_record(raw))
    for raw in domains["artifact"]:
        result["artifact"].append(build_artifact_record(raw))
        result["relationship"].extend(build_artifact_relationships(raw))
    for kind in ("technique", "tactic", "artifact"):
        for record in result[kind]:
            apply_ontology_text(record, ontology)
    for raw in domains["weakness"]:
        result["relationship"].extend(build_weakness_relationships(raw))

    result["relationship"].extend(build_mapping_relationships(domains["mapping"]))

    print(
        "[mitre-defend-parser] parsed "
        f"{len(domains['technique'])} techniques, "
        f"{len(domains['tactic'])} tactics, "
        f"{len(domains['artifact'])} artifacts, "
        f"{len(domains['weakness'])} weaknesses (relationships only, no entity records), "
        f"{len(domains['mapping'])} mapping rows, "
        f"{len(domains['ontology'])} ontology nodes"
    )
    entities = [r for kind in ("technique", "tactic", "artifact") for r in result[kind]]
    described = sum(1 for r in entities if r.get("description"))
    print(
        f"[mitre-defend-parser] text from the ontology: {described}/{len(entities)} entities "
        f"have a description, {sum(1 for r in entities if r.get('kb_article'))} a kb_article"
    )
    return result


def collapse_parallel_relationships(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One record per (`source_ref`, `relationship_type`, `target_ref`).

    The source states some links more than once, each statement carrying different
    attributes -- one defensive technique countering the same ATT&CK technique through four different digital-artifact pairs. Written straight through, those became parallel
    edges between the same two nodes, so `degree()` counted a node's statements rather
    than its neighbours, and retrieval that caps expansion by degree read the graph wrong.

    Nothing is dropped. Attributes identical across the group stay scalar; attributes that
    differ become a list holding one entry per original statement, in document order, and
    a field a statement did not carry holds `""` to keep that alignment (Neo4j rejects a
    list property containing `null`, so an empty string is the placeholder) -- so entry `i`
    of each of those lists belongs to the same original statement, and the original
    statements are recoverable exactly. A merged record names those fields in
    `merged_fields`, without which they could not be told apart from a field that was
    already multi-valued on a single statement -- CWE has `has_mitigation` links whose
    native two-entry `phase` sits on a record merged from two statements, where length
    alone cannot say which list is which. This runs after `clean_record()`, whose list
    handling dedupes and drops empty values, and would otherwise break the alignment
    those lists depend on.
    """
    grouped: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    for record in records:
        key = (record["source_ref"], record["relationship_type"], record["target_ref"])
        grouped.setdefault(key, []).append(record)

    collapsed: List[Dict[str, Any]] = []
    for group in grouped.values():
        if len(group) == 1:
            collapsed.append(group[0])
            continue
        merged = dict(group[0])
        merged_fields = []
        for field in dict.fromkeys(field for record in group for field in record if field != "id"):
            values = [record.get(field) for record in group]
            if all(value == values[0] for value in values):
                merged[field] = values[0]
            else:
                # `""` not `None`: these lists become Neo4j list properties, and Neo4j
                # rejects a null inside one. Only CWE hits this, on the 2 `child_of`
                # links where one view states an `ordinal` and the other does not.
                merged[field] = ["" if value is None else value for value in values]
                merged_fields.append(field)
        merged["merged_fields"] = merged_fields
        collapsed.append(merged)
    return collapsed


def write_outputs(result: Dict[str, List[Dict[str, Any]]], output_dir: Path, collected_at: str | None) -> Dict[str, int]:
    """Write every entity record to entities.json and every edge to relationships.json,
    concatenated in `result`'s own insertion order so reruns are byte-stable."""
    output_dir.mkdir(parents=True, exist_ok=True)
    files: Dict[str, List[Dict[str, Any]]] = {ENTITIES_FILENAME: [], RELATIONSHIPS_FILENAME: []}
    counts: Dict[str, int] = {}
    for key, records in result.items():
        target = RELATIONSHIPS_FILENAME if key in RELATIONSHIP_KEYS else ENTITIES_FILENAME
        cleaned = [clean_record(record) for record in records]
        if target == RELATIONSHIPS_FILENAME:
            cleaned = collapse_parallel_relationships(cleaned)
        files[target].extend(cleaned)
        counts[key] = len(cleaned)
    for filename, records in files.items():
        with (output_dir / filename).open("w", encoding="utf-8") as handle:
            json.dump([stamp_collected_at(record, collected_at) for record in records], handle, indent=2)
            handle.write("\n")
    return counts


def format_counts(counts: Dict[str, int], keys: Sequence[str]) -> str:
    """Total plus per-kind breakdown: `1193 (271 technique, 7 tactic, 915 artifact)`."""
    breakdown = ", ".join(f"{counts[key]} {key}" for key in keys if counts[key])
    return f"{sum(counts[key] for key in keys)} ({breakdown})"


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    default_input = script_dir.parent.parent / "data-acquisition" / "mitre-defend"

    parser = argparse.ArgumentParser(description="Trim D3FEND's JSON-LD domains down to a fixed field whitelist and extract relationships")
    parser.add_argument("--input", default=str(default_input), help=f"Path to the D3FEND crawler's workspace directory (default: {default_input})")
    parser.add_argument("--output-dir", default=str(script_dir), help=f"Directory to write entities.json / relationships.json (default: {script_dir})")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    output_dir = Path(args.output_dir)

    try:
        domains = {domain: load_domain(Path(args.input), domain) for domain in DOMAIN_FILES}
        collected_at = read_collected_at(Path(args.input) / "manifest.json")
        counts = write_outputs(parse(domains), output_dir, collected_at)
        entity_keys = [key for key in counts if key not in RELATIONSHIP_KEYS]
        print(
            f"[mitre-defend-parser] wrote {format_counts(counts, entity_keys)} entities to {ENTITIES_FILENAME} "
            f"and {counts['relationship']} relationships to {RELATIONSHIPS_FILENAME}, in {output_dir}"
        )
        return 0
    except (ParseError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
