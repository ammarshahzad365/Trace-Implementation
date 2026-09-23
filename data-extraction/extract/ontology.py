"""The vocabulary an LLM may use, and how it maps onto this graph.

Both lists are **open**, decided 2026-09-17 at the user's direction, replacing
the paper's closed seven entity types and seven triple patterns
(the four relation names that were the paper's alone went on 2026-09-23;
see `orient`):

- **Entity types** offered to the model are every node label the graph already
  holds (25, from the five structured catalogs), every STIX 2.1 domain object,
  and the STIX cyber-observable objects a report actually carries (hashes, IPs,
  domains ...). A text naming something none of these describes may be given a
  new type, which is written like any other -- the loader derives a label from
  it (`threat-actor` -> `ThreatActor`) and creates its constraint on the fly.
- **Relation types** offered are every relationship the graph holds and every
  STIX 2.1 relationship; a new name is allowed when none of those describes
  what the text states.

What stays fixed is *how the model names things*: it must copy an offered name
exactly, or write a new one in the same style. `normalise_type` and
`normalise_relation` fold case and punctuation, and an alias table maps the
words a report actually uses ("APT group", "C2 server", "CWE") onto the
offered type, so that a new type appears only where the vocabulary is
genuinely short, not where the model chose a synonym.

## Why the model writes free strings, not enum values

Both `type` and `relation` used to be JSON-schema enums with an `other`
escape. Measured on the relation side first: under constrained decoding the
model never once chose `other` -- for two malware families that share code it
tried `uses`, `subtechnique_of` and `targets` in turn. An enum makes the
escape value structurally unreachable in practice. So the schema constrains
only what the code can check afterwards (a relation's endpoints are enums of
the entities actually found), and canonicalising the *name* moved into this
module.

## Where the entities the paper cared about went

The paper's `vuln`/`technique`/`tool`/`group`/`asset`/`mitigation`/
`defend_technique` are now `vulnerability`/`attack-technique`/`tool`/
`intrusion-set`/`asset`/`attack-mitigation`/`defensive-technique`. The old
names survive as aliases, so the gold set and old proposals still resolve.
Per-type F1 against the paper's Table 4 is computed over that subset
(`PAPER_TYPES`).

## The mapping trap, still

The paper's `technique` means an *attack* technique. In this repo
`catalog/labels.py` maps the bare type `technique` to `DefensiveTechnique`
(D3FEND's word), and `x-mitre-asset` to `Asset`. The model never sees those
raw `type` values: it sees `attack-technique`, `defensive-technique`,
`asset`, and `EntityType.repo_type` carries what the loader expects.
"""

from __future__ import annotations

import re
from typing import Iterable, NamedTuple


class EntityType(NamedTuple):
    name: str  # what the model writes; kebab-case, STIX's word where STIX has one
    repo_type: str  # the `type` value sent to /ingest (catalog/labels.py fixes its label)
    label: str  # the Neo4j label a *new* node gets
    align: tuple[str, ...]  # labels alignment searches; a superset of `label`
    definition: str
    origin: str  # "graph" | "stix" | "both"


def _t(name: str, repo: str, label: str, align: tuple[str, ...], definition: str, origin: str) -> EntityType:
    return EntityType(name, repo, label, align, definition, origin)


# Grouped as the prompt shows them: what a report names most often first, the
# catalogs' structural entries last with a note that prose rarely states them.
# `origin` records where each comes from -- the graph (a label with nodes and
# usually a vector index), STIX 2.1, or both.
ENTITY_GROUPS: tuple[tuple[str, tuple[EntityType, ...]], ...] = (
    ("Actors, campaigns, malware and tools", (
        _t("intrusion-set", "intrusion-set", "IntrusionSet", ("IntrusionSet", "ThreatActor"),
           "a named adversary group tracked over time: an APT or threat group (APT41, Volt Typhoon, Hafnium)", "both"),
        _t("threat-actor", "threat-actor", "ThreatActor", ("ThreatActor", "IntrusionSet"),
           "a person or organisation behind attacks, when the text names one apart from its group", "stix"),
        _t("campaign", "campaign", "Campaign", ("Campaign",),
           "a named series of attacks over a period (Operation Aurora, a 2023 espionage campaign)", "both"),
        _t("malware", "malware", "Malware", ("Malware", "Tool"),
           "malicious software: backdoor, trojan, ransomware, web shell, loader, implant, rootkit", "both"),
        _t("tool", "tool", "Tool", ("Tool", "Malware"),
           "legitimate or dual-use software an attacker uses (Mimikatz, PsExec, 7-Zip, Cobalt Strike)", "both"),
    )),
    ("Attack knowledge", (
        _t("attack-technique", "attack-technique", "AttackTechnique", ("AttackTechnique",),
           "what the attacker does, as an ATT&CK-style technique (credential dumping, DLL side-loading; T-ids)", "graph"),
        _t("attack-pattern", "attack-pattern", "AttackPattern", ("AttackPattern", "AttackTechnique"),
           "a general way of attacking as CAPEC describes it (CAPEC-ids); prefer attack-technique for ATT&CK", "both"),
        _t("tactic", "x-mitre-tactic", "AttackTactic", ("AttackTactic",),
           "the attacker's goal at a stage: initial access, persistence, exfiltration (TA-ids)", "graph"),
    )),
    ("Vulnerabilities and weaknesses", (
        _t("vulnerability", "vulnerability", "Vulnerability", ("Vulnerability",),
           "a specific flaw in a product, named or with a CVE identifier", "both"),
        _t("weakness", "weakness", "Weakness", ("Weakness",),
           "a class of flaw as CWE describes it (buffer overflow, SQL injection; CWE-ids)", "graph"),
        _t("consequence", "consequence", "Consequence", ("Consequence",),
           "a technical impact a weakness leads to (denial of service, data loss, code execution)", "graph"),
    )),
    ("Defences", (
        _t("attack-mitigation", "attack-mitigation", "AttackMitigation",
           ("AttackMitigation", "CourseOfAction", "Mitigation"),
           "an ATT&CK mitigation: a defensive measure against a technique (M-ids)", "graph"),
        _t("course-of-action", "course-of-action", "CourseOfAction",
           ("CourseOfAction", "AttackMitigation", "Mitigation"),
           "a recommended action: apply a patch, change a configuration, restrict a port", "both"),
        _t("mitigation", "mitigation", "Mitigation", ("Mitigation", "AttackMitigation", "CourseOfAction"),
           "how to fix or avoid a weakness, as CWE describes it", "graph"),
        _t("defensive-technique", "technique", "DefensiveTechnique", ("DefensiveTechnique",),
           "a named defensive technique a defender performs (D3FEND: process lineage analysis, file hashing)", "graph"),
        _t("defensive-tactic", "tactic", "DefensiveTactic", ("DefensiveTactic",),
           "a defender's goal: harden, detect, isolate, deceive, evict (D3FEND)", "graph"),
        _t("detection-method", "detection-method", "DetectionMethod", ("DetectionMethod",),
           "a way to find a weakness: static analysis, fuzzing, manual review", "graph"),
        _t("detection-strategy", "x-mitre-detection-strategy", "DetectionStrategy", ("DetectionStrategy",),
           "an ATT&CK detection strategy for a technique (DET-ids)", "graph"),
        _t("analytic", "x-mitre-analytic", "Analytic", ("Analytic",),
           "a concrete detection rule or query (AN-ids)", "graph"),
        _t("data-component", "x-mitre-data-component", "DataComponent", ("DataComponent",),
           "a kind of data a detection reads: process creation logs, network flows (DC-ids)", "graph"),
        _t("artifact", "artifact", "Artifact", ("Artifact",),
           "a digital artifact a technique acts on: a file, process, credential, network traffic (D3FEND)", "graph"),
    )),
    ("Victims, infrastructure and places", (
        _t("asset", "x-mitre-asset", "Asset", ("Asset",),
           "a system, device, product or component that is attacked or affected (Exchange Server, SOHO routers, a PLC)", "graph"),
        _t("identity", "identity", "Identity", ("Identity",),
           "a victim or party: an organisation, sector or role (telecommunications providers, a law firm, a vendor)", "stix"),
        _t("location", "location", "Location", ("Location",),
           "a country or region", "stix"),
        _t("infrastructure", "infrastructure", "Infrastructure", ("Infrastructure",),
           "systems the attacker operates or abuses: C2 servers, hosting, botnets, accounts used to exfiltrate", "stix"),
        _t("platform", "platform", "Platform", ("Platform",),
           "an operating system, language or technology a weakness applies to", "graph"),
    )),
    ("Observables and indicators", (
        _t("indicator", "indicator", "Indicator", ("Indicator",),
           "a detectable pattern given as an IoC when the text does not say which kind; prefer the specific types below", "stix"),
        _t("file", "file", "File", ("File",),
           "a file named by path, name or hash (an executable, a document, a DLL)", "stix"),
        _t("ipv4-addr", "ipv4-addr", "Ipv4Addr", ("Ipv4Addr",), "an IPv4 address", "stix"),
        _t("ipv6-addr", "ipv6-addr", "Ipv6Addr", ("Ipv6Addr",), "an IPv6 address", "stix"),
        _t("domain-name", "domain-name", "DomainName", ("DomainName",), "a domain name", "stix"),
        _t("url", "url", "Url", ("Url",), "a URL", "stix"),
        _t("email-addr", "email-addr", "EmailAddr", ("EmailAddr",), "an email address", "stix"),
        _t("email-message", "email-message", "EmailMessage", ("EmailMessage",),
           "a specific email, such as a phishing lure named by subject", "stix"),
        _t("process", "process", "Process", ("Process",), "a running program named as such (svchost.exe, lsass)", "stix"),
        _t("user-account", "user-account", "UserAccount", ("UserAccount",), "a user or service account", "stix"),
        _t("software", "software", "Software", ("Software",),
           "installed software named as a product or version, not as an attacker's tool", "stix"),
        _t("windows-registry-key", "windows-registry-key", "WindowsRegistryKey", ("WindowsRegistryKey",),
           "a Windows registry key", "stix"),
        _t("x509-certificate", "x509-certificate", "X509Certificate", ("X509Certificate",),
           "a code-signing or TLS certificate", "stix"),
        _t("mutex", "mutex", "Mutex", ("Mutex",), "a mutex name", "stix"),
        _t("autonomous-system", "autonomous-system", "AutonomousSystem", ("AutonomousSystem",),
           "an autonomous system (AS number)", "stix"),
        _t("mac-addr", "mac-addr", "MacAddr", ("MacAddr",), "a MAC address", "stix"),
        _t("network-traffic", "network-traffic", "NetworkTraffic", ("NetworkTraffic",),
           "a described connection or protocol flow (beaconing over HTTPS to port 443)", "stix"),
        _t("directory", "directory", "Directory", ("Directory",), "a file-system directory", "stix"),
    )),
    ("Documents and analysis (rare in prose)", (
        _t("report", "report", "Report", ("Report",), "a published report or advisory cited by name", "stix"),
        _t("malware-analysis", "malware-analysis", "MalwareAnalysis", ("MalwareAnalysis",),
           "a specific analysis result of a sample (a sandbox run, a detection verdict)", "stix"),
        _t("observed-data", "observed-data", "ObservedData", ("ObservedData",),
           "a sighting: something observed on a system at a time", "stix"),
        _t("grouping", "grouping", "Grouping", ("Grouping",), "a named set of related objects", "stix"),
        _t("note", "note", "Note", ("Note",), "an analyst's note attached to something", "stix"),
        _t("opinion", "opinion", "Opinion", ("Opinion",), "an assessment of how much something is agreed with", "stix"),
    )),
    ("Catalog structure (rare in prose)", (
        _t("category", "category", "Category", ("Category",), "a CWE category grouping weaknesses", "graph"),
        _t("view", "view", "View", ("View",), "a CWE view (a curated list of weaknesses)", "graph"),
        _t("matrix", "x-mitre-matrix", "AttackMatrix", ("AttackMatrix",), "an ATT&CK matrix (Enterprise, ICS, Mobile)", "graph"),
    )),
)

ENTITY_TYPES: dict[str, EntityType] = {
    entity.name: entity for _, group in ENTITY_GROUPS for entity in group
}

# The paper's names and the words a report uses, mapped onto an offered type.
# The purpose is that a synonym lands on the type, not on a duplicate: a
# model that writes "APT group" has not found something the vocabulary lacks.
# Keys are already normalised (see `normalise_type`).
TYPE_ALIASES: dict[str, str] = {
    # the paper's seven, as the code and the gold set used to spell them
    "vuln": "vulnerability", "group": "intrusion-set", "technique": "attack-technique",
    "defend-technique": "defensive-technique", "defend": "defensive-technique",
    # actors
    "apt": "intrusion-set", "apt-group": "intrusion-set", "threat-group": "intrusion-set",
    "adversary": "threat-actor", "actor": "threat-actor", "attacker": "threat-actor",
    "operation": "campaign",
    # code
    "backdoor": "malware", "trojan": "malware", "ransomware": "malware", "web-shell": "malware",
    "webshell": "malware", "rat": "malware", "implant": "malware", "loader": "malware",
    "rootkit": "malware", "worm": "malware", "botnet": "malware", "malware-family": "malware",
    "utility": "tool", "framework": "tool", "exploit": "tool", "script": "tool",
    # knowledge
    "ttp": "attack-technique", "attack": "attack-technique", "sub-technique": "attack-technique",
    "subtechnique": "attack-technique", "capec": "attack-pattern", "cwe": "weakness",
    "cve": "vulnerability", "flaw": "vulnerability", "bug": "vulnerability", "impact": "consequence",
    # defences
    "patch": "course-of-action", "fix": "course-of-action", "remediation": "course-of-action",
    "countermeasure": "course-of-action", "recommendation": "course-of-action",
    "defense": "defensive-technique", "defence": "defensive-technique",
    "d3fend-technique": "defensive-technique", "detection": "detection-strategy",
    # victims and infrastructure
    "device": "asset", "system": "asset", "product": "asset", "component": "asset",
    "target": "asset", "victim": "identity", "organization": "identity", "organisation": "identity",
    "sector": "identity", "industry": "identity", "company": "identity", "vendor": "identity",
    "country": "location", "region": "location", "c2": "infrastructure", "c2-server": "infrastructure",
    "server": "infrastructure", "command-and-control": "infrastructure", "hosting": "infrastructure",
    "os": "platform", "operating-system": "platform",
    # observables
    "ioc": "indicator", "hash": "file", "sha256": "file", "md5": "file", "executable": "file",
    "ip": "ipv4-addr", "ip-address": "ipv4-addr", "ipv4": "ipv4-addr", "ipv6": "ipv6-addr",
    "domain": "domain-name", "hostname": "domain-name", "email": "email-addr",
    "account": "user-account", "registry-key": "windows-registry-key", "certificate": "x509-certificate",
    "cert": "x509-certificate", "asn": "autonomous-system",
}

_TYPE_NAME = re.compile(r"^[a-z][a-z0-9-]{1,40}$")
_SPLIT = re.compile(r"[-_.\s]+")


def _derived_label(type_name: str) -> str:
    """`threat-actor` -> `ThreatActor`, as `graphload.naming.to_label` will."""
    return "".join(part[:1].upper() + part[1:] for part in _SPLIT.split(type_name) if part)


OTHER = "other"  # kept so proposals saved before 2026-09-17 still load; no longer written

# The genres section 3.1.1 names. The value is what the extraction prompt calls
# the document, which the model does read -- "an APT report" primes differently
# from "a document". Genre no longer restricts the types offered; it still
# decides whether the relevance screen runs (papers only).
GENRES: dict[str, str] = {
    "apt-report": "an APT (advanced persistent threat) report",
    "repair-notice": "a vendor repair notice or security advisory",
    "paper": "an academic paper on attack or defense techniques",
}

# The paper's seven, by their new names -- the subset per-type F1 is reported
# on against Table 4.
PAPER_TYPES: tuple[str, ...] = (
    "vulnerability", "attack-technique", "tool", "intrusion-set", "asset",
    "attack-mitigation", "defensive-technique",
)

# Types whose extracted name is a *name* (a proper noun), so that an existing
# name contained in it is evidence of identity ("Cobalt Strike beacon" is
# S0154). Not for the paraphrased types below.
PROPER_NOUN_TYPES: frozenset[str] = frozenset({
    "intrusion-set", "threat-actor", "campaign", "malware", "tool", "vulnerability",
    "asset", "identity", "infrastructure", "software", "platform", "location",
})

# Types a report refers back to as "the actor", "the group", "it".
ACTOR_TYPES: frozenset[str] = frozenset({"intrusion-set", "threat-actor"})

# Types whose name is the model's paraphrase of a behaviour, so evidence for a
# relation is judged by overlap with the description rather than by the name.
PARAPHRASED_TYPES: frozenset[str] = frozenset({
    "attack-technique", "attack-pattern", "tactic", "defensive-technique", "defensive-tactic",
    "detection-method", "detection-strategy", "analytic", "consequence", "weakness",
})

_LABEL_TO_TYPE: dict[str, str] = {}
for _entity in ENTITY_TYPES.values():
    _LABEL_TO_TYPE.setdefault(_entity.label, _entity.name)
for _entity in ENTITY_TYPES.values():
    for _label in _entity.align:
        _LABEL_TO_TYPE.setdefault(_label, _entity.name)


def normalise_type(raw: str) -> str | None:
    """`Threat Actor` -> `threat-actor`; `APT group` -> `intrusion-set`;
    `Backdoor` -> `malware`; `victim-sector` -> `victim-sector` (a new type).
    None if nothing usable remains."""
    cleaned = re.sub(r"[^a-z0-9]+", "-", raw.strip().lower()).strip("-")
    cleaned = re.sub(r"-+", "-", cleaned)
    cleaned = re.sub(r"^(?:the|a|an)-", "", cleaned)
    if not cleaned:
        return None
    for form in (cleaned, cleaned[:-1] if cleaned.endswith("s") and not cleaned.endswith("ss") else cleaned):
        if form in ENTITY_TYPES:
            return form
        if form in TYPE_ALIASES:
            return TYPE_ALIASES[form]
    return cleaned if _TYPE_NAME.match(cleaned) else None


def is_known_type(name: str) -> bool:
    return name in ENTITY_TYPES


def entity_types() -> tuple[str, ...]:
    """Every offered type name, in prompt order."""
    return tuple(ENTITY_TYPES)


def repo_type(type_name: str) -> str:
    """`asset` -> `x-mitre-asset`; a new type is its own repo type, and the
    loader derives a label from it."""
    entity = ENTITY_TYPES.get(type_name)
    return entity.repo_type if entity else type_name


def repo_label(type_name: str) -> str:
    """The label a *new* node of this type gets."""
    entity = ENTITY_TYPES.get(type_name)
    return entity.label if entity else _derived_label(type_name)


def align_labels(type_name: str) -> tuple[str, ...]:
    """The labels alignment searches for this type. `tool` -> Tool and Malware."""
    entity = ENTITY_TYPES.get(type_name)
    return entity.align if entity else (_derived_label(type_name),)


def paper_type_for_label(label: str) -> str | None:
    """Which offered type does a graph label belong to? `Malware` -> `malware`."""
    return _LABEL_TO_TYPE.get(label)


def all_types() -> Iterable[str]:
    return ENTITY_TYPES.keys()


# --------------------------------------------------------------------------
# Relations
# --------------------------------------------------------------------------


class Pattern(NamedTuple):
    source: str
    relation: str
    target: str


# What each relation means, in the prompts' words, with its direction. Three
# groups, all offered: what a report states most often (STIX's core and the
# graph's), the rest of STIX 2.1's relationships, and the structured
# catalogs' own. Definitions follow each source's meaning. With the catalog
# types now extractable, the catalog relations can be right between extracted
# entities, which is why they are offered again after being withdrawn on
# 2026-09-11 (then, `has_analytic` was used for tool -> tool because nothing
# could be an analytic; now an analytic can be extracted).
REPORT_RELATIONS: dict[str, str] = {
    "uses": "the subject makes use of the object as an instrument: a group, campaign or actor uses a malware, tool, technique or infrastructure; a malware or tool carries out a technique; a technique is performed with a tool. Never for a victim system -- that is 'targets'",
    "targets": "the group, actor, campaign, malware, tool or technique attacks, is aimed at or compromises the asset, identity, location or vulnerability",
    "exploits": "the malware or tool exploits the vulnerability",
    "attributed_to": "the campaign or intrusion set is attributed to the group or actor; the actor to a real-world identity",
    "communicates_with": "the malware or infrastructure talks to the infrastructure, address, domain or URL",
    "beacons_to": "the malware checks in with the command-and-control infrastructure",
    "exfiltrates_to": "the malware or actor sends stolen data to the infrastructure",
    "drops": "the malware or tool writes and runs the malware, tool or file",
    "downloads": "the malware or tool retrieves the malware, tool or file",
    "delivers": "the attack pattern, infrastructure or tool delivers the malware to the victim",
    "compromises": "the group, actor or campaign takes control of the infrastructure or asset",
    "hosts": "the infrastructure, group or actor hosts the malware, tool or infrastructure",
    "owns": "the group or actor owns the infrastructure",
    "indicates": "the indicator or observable indicates the presence of the malware, tool, campaign, group or infrastructure",
    "mitigates": "the mitigation or course of action reduces or blocks the attack technique, pattern, malware, tool or vulnerability",
    "remediates": "the course of action removes the malware or fixes the vulnerability",
    "counters": "the defensive technique counters or defeats the attack technique",
    "variant_of": "the malware is a variant or new version of the malware",
    "impersonates": "the actor, malware or infrastructure pretends to be the identity, process or file",
    "originates_from": "the group, actor, campaign or malware comes from the location",
    "located_at": "the identity, actor, asset or infrastructure is in the location",
    "subtechnique_of": "the technique is a more specific form of the parent technique",
    "authored_by": "the malware or tool was written by the actor or group",
}

STIX_RELATIONS: dict[str, str] = {
    "consists_of": "the infrastructure is made up of the systems, addresses or domains",
    "controls": "the infrastructure or malware controls the malware or infrastructure",
    "has": "the infrastructure, tool or asset has the vulnerability -- only for vulnerabilities; a file's hash, a malware's mutex or registry key are not 'has', write what the text says (e.g. hash_of, creates_mutex, stores_configuration_in)",
    "resolves_to": "the domain name resolves to the IP address",
    "belongs_to": "the IP address belongs to the autonomous system",
    "based_on": "the indicator is based on the observed data",
    "investigates": "the course of action investigates the indicator",
    "characterizes": "the malware analysis characterises the malware",
    "analysis_of": "the malware analysis is an analysis of the malware or file",
    "derived_from": "the object was derived from the other (a report from its sources)",
    "duplicate_of": "the object is a duplicate of the other",
}

CATALOG_RELATIONS: dict[str, str] = {
    # ATT&CK
    "detects": "the detection strategy or analytic detects the attack technique",
    "has_tactic": "the technique serves the tactic (its goal, e.g. initial access, persistence)",
    "accesses": "the attack technique accesses the artifact (a file, process, credential, network traffic ...)",
    "creates": "the attack technique creates the artifact",
    "executes": "the attack technique executes the artifact",
    "modifies": "the attack technique modifies the artifact",
    # D3FEND
    "hardens": "the defensive technique hardens the artifact",
    "observes": "the defensive technique observes or monitors the artifact",
    "constrains": "the defensive technique constrains or restricts the artifact",
    "restores": "the defensive technique restores the artifact",
    "enables": "the defensive technique enables the defensive tactic",
    "has_analytic": "the detection strategy is made up of the analytic",
    "uses_data_component": "the analytic reads the data component (a log, a sensor ...)",
    "weakness_of": "the weakness is a weakness of the artifact",
    # CWE / CAPEC
    "child_of": "the weakness, attack pattern or artifact is a more specific form of the other",
    "peer_of": "the two weaknesses or attack patterns are peers",
    "can_precede": "the weakness or attack pattern can come before the other in a chain",
    "can_also_be": "the weakness can also be classified as the other weakness",
    "requires": "the weakness requires the other weakness to be present",
    "starts_with": "the weakness chain starts with the other weakness",
    "has_consequence": "the weakness leads to the consequence (e.g. denial of service)",
    "has_detection_method": "the weakness can be found by the detection method",
    "has_mitigation": "the weakness is reduced by the mitigation",
    "has_observed_example": "the weakness has the vulnerability as a real observed example",
    "has_member": "the category, view or matrix contains the weakness, category or tactic",
    "applies_to_platform": "the weakness applies to the platform (a language, OS or technology)",
}

# Known to the pipeline but not offered: NVD's `related_to` is a cross-reference
# (a CVE to its weakness class), not a statement, and offered it became the
# fallback for everything -- "shares code with" and "bundled with" both came
# back as `related_to` -- which is exactly the outcome the new-name route exists
# to prevent. STIX has the same relationship with the same problem.
UNOFFERED_RELATIONS: dict[str, str] = {
    "related_to": "the catalogs' generic cross-reference; never produced from text",
    "revoked_by": "the catalog entry was retired and replaced by the other (ATT&CK bookkeeping); never produced from text",
}

RELATION_GROUPS: tuple[tuple[str, dict[str, str]], ...] = (
    ("Common in reports", REPORT_RELATIONS),
    ("More STIX relationships", STIX_RELATIONS),
    ("From the structured catalogs (ATT&CK, D3FEND, CWE, CAPEC)", CATALOG_RELATIONS),
)

RELATION_DEFINITIONS: dict[str, str] = {
    **REPORT_RELATIONS, **STIX_RELATIONS, **CATALOG_RELATIONS, **UNOFFERED_RELATIONS,
}


# Every (source label, relation, target label) the graph held on 2026-09-11,
# measured with `MATCH (a)-[r]->(b) RETURN type(r), labels(a)[0],
# labels(b)[0]`, in type names. Our own test commits excluded.
GRAPH_PATTERNS: tuple[Pattern, ...] = tuple(
    Pattern(s, r, t) for s, r, t in (
        ("attack-technique", "accesses", "artifact"),
        ("weakness", "applies_to_platform", "platform"),
        ("campaign", "attributed_to", "intrusion-set"),
        ("weakness", "can_also_be", "weakness"),
        ("attack-pattern", "can_precede", "attack-pattern"),
        ("weakness", "can_precede", "weakness"),
        ("weakness", "child_of", "weakness"),
        ("artifact", "child_of", "artifact"),
        ("attack-pattern", "child_of", "attack-pattern"),
        ("defensive-technique", "constrains", "artifact"),
        ("defensive-technique", "counters", "attack-technique"),
        ("attack-technique", "creates", "artifact"),
        ("detection-strategy", "detects", "attack-technique"),
        ("defensive-technique", "enables", "defensive-tactic"),
        ("attack-technique", "executes", "artifact"),
        ("defensive-technique", "hardens", "artifact"),
        ("detection-strategy", "has_analytic", "analytic"),
        ("weakness", "has_consequence", "consequence"),
        ("weakness", "has_detection_method", "detection-method"),
        ("category", "has_member", "weakness"),
        ("view", "has_member", "weakness"),
        ("view", "has_member", "category"),
        ("category", "has_member", "category"),
        ("matrix", "has_member", "tactic"),
        ("weakness", "has_mitigation", "mitigation"),
        ("weakness", "has_observed_example", "vulnerability"),
        ("attack-technique", "has_tactic", "tactic"),
        ("attack-mitigation", "mitigates", "attack-technique"),
        ("course-of-action", "mitigates", "attack-pattern"),
        ("attack-technique", "modifies", "artifact"),
        ("defensive-technique", "observes", "artifact"),
        ("weakness", "peer_of", "weakness"),
        ("attack-pattern", "peer_of", "attack-pattern"),
        ("vulnerability", "related_to", "weakness"),
        ("vulnerability", "related_to", "category"),
        ("weakness", "related_to", "attack-pattern"),
        ("attack-pattern", "related_to", "attack-technique"),
        ("weakness", "requires", "weakness"),
        ("defensive-technique", "restores", "artifact"),
        ("attack-technique", "revoked_by", "attack-technique"),
        ("intrusion-set", "revoked_by", "intrusion-set"),
        ("malware", "revoked_by", "malware"),
        ("weakness", "starts_with", "weakness"),
        ("attack-technique", "subtechnique_of", "attack-technique"),
        ("attack-technique", "targets", "asset"),
        ("malware", "uses", "attack-technique"),
        ("intrusion-set", "uses", "attack-technique"),
        ("campaign", "uses", "attack-technique"),
        ("tool", "uses", "attack-technique"),
        ("intrusion-set", "uses", "malware"),
        ("intrusion-set", "uses", "tool"),
        ("campaign", "uses", "malware"),
        ("campaign", "uses", "tool"),
        ("analytic", "uses_data_component", "data-component"),
        ("weakness", "weakness_of", "artifact"),
    )
)

# STIX 2.1's relationship summary table (section 4 of the specification),
# reduced to the types offered above. `attack-pattern` in STIX covers what
# this graph splits into attack-technique and attack-pattern, so both appear.
_STIX_TABLE: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("attack-pattern", "delivers", ("malware",)),
    ("attack-pattern", "targets", ("identity", "location", "vulnerability")),
    ("attack-pattern", "uses", ("malware", "tool")),
    ("attack-technique", "delivers", ("malware",)),
    ("attack-technique", "targets", ("identity", "location", "vulnerability")),
    ("attack-technique", "uses", ("malware", "tool")),
    ("campaign", "attributed_to", ("intrusion-set", "threat-actor")),
    ("campaign", "compromises", ("infrastructure",)),
    ("campaign", "originates_from", ("location",)),
    ("campaign", "targets", ("identity", "location", "vulnerability")),
    ("campaign", "uses", ("attack-pattern", "attack-technique", "infrastructure", "malware", "tool")),
    ("course-of-action", "investigates", ("indicator",)),
    ("course-of-action", "mitigates", ("attack-pattern", "attack-technique", "indicator", "malware", "tool", "vulnerability")),
    ("course-of-action", "remediates", ("malware", "vulnerability")),
    ("identity", "located_at", ("location",)),
    ("indicator", "indicates", ("attack-pattern", "attack-technique", "campaign", "infrastructure", "intrusion-set", "malware", "threat-actor", "tool")),
    ("indicator", "based_on", ("observed-data",)),
    ("infrastructure", "communicates_with", ("infrastructure", "ipv4-addr", "ipv6-addr", "domain-name", "url")),
    ("infrastructure", "consists_of", ("infrastructure", "observed-data", "ipv4-addr", "domain-name")),
    ("infrastructure", "controls", ("infrastructure", "malware")),
    ("infrastructure", "delivers", ("malware",)),
    ("infrastructure", "has", ("vulnerability",)),
    ("infrastructure", "hosts", ("tool", "malware", "infrastructure")),
    ("infrastructure", "located_at", ("location",)),
    ("infrastructure", "uses", ("infrastructure",)),
    ("intrusion-set", "attributed_to", ("threat-actor",)),
    ("intrusion-set", "compromises", ("infrastructure",)),
    ("intrusion-set", "hosts", ("infrastructure",)),
    ("intrusion-set", "owns", ("infrastructure",)),
    ("intrusion-set", "originates_from", ("location",)),
    ("intrusion-set", "targets", ("identity", "location", "vulnerability", "asset")),
    ("intrusion-set", "uses", ("attack-pattern", "attack-technique", "infrastructure", "malware", "tool")),
    ("malware", "authored_by", ("threat-actor", "intrusion-set")),
    ("malware", "beacons_to", ("infrastructure",)),
    ("malware", "exfiltrates_to", ("infrastructure",)),
    ("malware", "communicates_with", ("ipv4-addr", "ipv6-addr", "domain-name", "url")),
    ("malware", "controls", ("malware",)),
    ("malware", "downloads", ("malware", "tool", "file")),
    ("malware", "drops", ("malware", "tool", "file")),
    ("malware", "exploits", ("vulnerability",)),
    ("malware", "originates_from", ("location",)),
    ("malware", "targets", ("identity", "infrastructure", "location", "vulnerability", "asset")),
    ("malware", "uses", ("attack-pattern", "attack-technique", "infrastructure", "malware", "tool")),
    ("malware", "variant_of", ("malware",)),
    ("malware-analysis", "characterizes", ("malware",)),
    ("malware-analysis", "analysis_of", ("malware", "file")),
    ("threat-actor", "attributed_to", ("identity",)),
    ("threat-actor", "compromises", ("infrastructure",)),
    ("threat-actor", "hosts", ("infrastructure",)),
    ("threat-actor", "owns", ("infrastructure",)),
    ("threat-actor", "impersonates", ("identity",)),
    ("threat-actor", "located_at", ("location",)),
    ("threat-actor", "targets", ("identity", "location", "vulnerability", "asset")),
    ("threat-actor", "uses", ("attack-pattern", "attack-technique", "infrastructure", "malware", "tool")),
    ("tool", "delivers", ("malware",)),
    ("tool", "drops", ("malware",)),
    ("tool", "has", ("vulnerability",)),
    ("tool", "targets", ("identity", "infrastructure", "location", "vulnerability", "asset")),
    ("tool", "uses", ("infrastructure",)),
    ("domain-name", "resolves_to", ("ipv4-addr", "ipv6-addr")),
    ("ipv4-addr", "belongs_to", ("autonomous-system",)),
    ("ipv6-addr", "belongs_to", ("autonomous-system",)),
)

STIX_PATTERNS: tuple[Pattern, ...] = tuple(
    Pattern(source, relation, target)
    for source, relation, targets in _STIX_TABLE
    for target in targets
)

ALL_PATTERNS: frozenset[Pattern] = frozenset((*GRAPH_PATTERNS, *STIX_PATTERNS))

# A proposed relation name the writer will accept as a Neo4j relationship type
# once uppercased: snake_case, letters and digits, sensible length.
_RELATION_NAME = re.compile(r"^[a-z][a-z0-9_]{1,40}$")


def relation_names() -> tuple[str, ...]:
    """Every relation the model may pick by name, in prompt order."""
    return tuple(name for _, group in RELATION_GROUPS for name in group)


def normalise_relation(name: str) -> str | None:
    """`Exfiltrates To` -> `exfiltrates_to`; `beacons-to` -> `beacons_to`; None
    if nothing usable remains.

    A proposed name reaches Neo4j as a relationship type (uppercased by the
    writer), so it must be an identifier. Anything else -- an empty string, a
    sentence, punctuation -- is refused here rather than written as a type
    nobody will ever query.
    """
    cleaned = re.sub(r"[^a-z0-9]+", "_", name.strip().lower()).strip("_")
    cleaned = re.sub(r"_+", "_", cleaned)
    return cleaned if _RELATION_NAME.match(cleaned) else None


def is_known_relation(name: str) -> bool:
    return name in RELATION_DEFINITIONS


def typical_patterns(source_type: str | None = None) -> tuple[Pattern, ...]:
    """The patterns shown to the model as typical directions -- the graph's
    and STIX's, minus the unoffered relations. Optionally only those with this
    source type."""
    seen: dict[Pattern, None] = {}
    for pattern in (*GRAPH_PATTERNS, *STIX_PATTERNS):
        if pattern.relation in UNOFFERED_RELATIONS:
            continue
        if source_type is None or pattern.source == source_type:
            seen.setdefault(pattern, None)
    return tuple(seen)


def orient(source_type: str, relation: str, target_type: str) -> tuple[bool, str]:
    """Does a known pattern fix this relation's direction and name?

    Returns (swap, relation). The schema, not the model, owns direction:
    STIX fixes most directions: a model that returns `Mimikatz beacons_to
    SilverPaw` has the fact right and the arrow wrong. When the reversed pair
    is a known pattern and the given one is not, swap.

    Three retypings on top, because the definitions say so and the model does
    not always listen: `uses` with an asset, identity, location or
    vulnerability as object is `targets` ("Volt Typhoon uses Fortinet devices"
    survived two prompt rules, and STIX gives an actor `targets` a
    vulnerability); an actor or campaign that `exploits` a vulnerability
    likewise `targets` it, since STIX reserves `exploits` for malware and
    tools; and an actor that "drops" or "delivers" something `uses` it.

    The paper's `used_by` (vulnerability -> group) used to be the answer to
    the second of those. It was removed on 2026-09-23 along with `discovers`,
    `causes` and `mitigated_by`: those four are the paper's alone, name the
    same facts STIX already names, and nothing in this graph uses them.
    `uses` and `targets` are ATT&CK's own -- 20,187 edges -- and stay.
    """
    if relation == "uses" and target_type in {"asset", "identity", "location", "vulnerability"}:
        relation = "targets"
    # STIX defines drops/downloads/delivers for malware, tools and
    # infrastructure; an actor that "deployed" something uses it.
    if relation in {"drops", "downloads", "delivers"} and source_type in {*ACTOR_TYPES, "campaign"}:
        relation = "uses"
    # STIX reserves `exploits` for malware and tools; an actor or campaign
    # that exploits a vulnerability targets it.
    if relation == "exploits" and target_type == "vulnerability" and source_type in {
        *ACTOR_TYPES, "campaign"
    }:
        relation = "targets"
    forward = Pattern(source_type, relation, target_type) in ALL_PATTERNS
    backward = Pattern(target_type, relation, source_type) in ALL_PATTERNS
    return (backward and not forward), relation


# --------------------------------------------------------------------------
# Identifiers
# --------------------------------------------------------------------------

# Identifiers that name a node directly, sampled from what `data-preprocessing/`
# actually emits rather than from the paper: CVE-1999-0001, CWE-5, CAPEC-85,
# T1003.008, TA0009, M1036, G1028, S0066, C0028, A0008, AN0001, DC0103, DET0210.
#
# Two things to note. `S####` is shared by `malware` and `tool`, so a match tells
# us the id but *not* the type -- which is why `find_identifiers` returns ids
# only and the caller resolves the label from the graph. And D3FEND is absent on
# purpose: its ids in this graph are CamelCase names (`AccessMediation`), not the
# `D3-PLA` form the paper's Figure 3 shows, and a CamelCase word cannot be told
# from ordinary prose by a regex. Defensive techniques therefore reach their node
# through embedding alignment or not at all.
_IDENTIFIER_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
    re.compile(r"\bCWE-\d{1,4}\b", re.I),
    re.compile(r"\bCAPEC-\d{1,4}\b", re.I),
    re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
    re.compile(r"\bTA\d{4}\b"),
    re.compile(r"\bM\d{4}\b"),
    re.compile(r"\bG\d{4}\b"),
    re.compile(r"\bS\d{4}\b"),
    re.compile(r"\bC\d{4}\b"),
    re.compile(r"\bA\d{4}\b"),
    re.compile(r"\bAN\d{4}\b"),
    re.compile(r"\bDC\d{4}\b"),
    re.compile(r"\bDET\d{4}\b"),
)

# Words that label a serial number without being part of it, so that "Item 3"
# and "Ref. 44" count as serials while "Exchange Server 2019" does not.
_FILLER_WORDS = frozenset(
    {"no", "nr", "num", "number", "item", "entry", "ref", "reference", "id", "sn", "serial"}
)
_WORDS = re.compile(r"[A-Za-z]+")


def find_identifiers(text: str) -> list[str]:
    """Every standardised identifier in `text`, uppercased, in first-seen order.

    Type is deliberately not inferred -- `S0066` could be malware or a tool, and
    the graph already knows which. The caller looks the id up and adopts
    whatever label it finds.
    """
    seen: dict[str, None] = {}
    for pattern in _IDENTIFIER_PATTERNS:
        for match in pattern.finditer(text):
            seen.setdefault(match.group(0).upper(), None)
    return list(seen)


def is_serial_only(name: str) -> bool:
    """Is this name just a number with decoration -- `SN-4471`, `#12`, `Item 3`?

    Section 3.2.3 drops nodes whose names "only contain serial numbers without
    valid information", but only when they are also isolated, so a false positive
    here is survivable and a false negative merely leaves a dull node in place.

    The hard part is that `CVE-2021-26855` is also mostly digits and is the
    opposite of uninformative -- so a name that parses as a standard identifier
    is never a serial. After that the test is simply whether any meaningful word
    remains once filler is removed.

    Written as a scan rather than one regex on purpose: the obvious pattern
    nests two unbounded character classes and backtracks super-linearly, and
    these names ultimately come from documents we did not write.
    """
    stripped = name.strip()
    if not stripped or not any(character.isdigit() for character in stripped):
        return False
    if find_identifiers(stripped):
        return False
    # Any word that is not filler makes it a name. An earlier version required
    # the surviving letters to exceed three, which dropped `7-Zip` -- a real
    # tool -- as a serial. Keeping a dull node is cheaper than losing a real one.
    return not any(word.lower() not in _FILLER_WORDS for word in _WORDS.findall(stripped))
