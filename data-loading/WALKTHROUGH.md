# `data-loading/` explained like you're five

This is a plain-language walkthrough of **everything** in the `data-loading/`
folder: what each file does, why it exists, and what actually happened when it
ran. The design *reasoning* lives in [README.md](README.md) and
[ARCHITECTURE.md](ARCHITECTURE.md); this file is the friendly version.

---

## 1. The big picture, in one story

Imagine five different **encyclopedias** about computer security. They all sit in
boxes, cut into millions of little paper cards:

| Encyclopedia | What it's about | Card example |
|---|---|---|
| **CVE** | actual broken things found in real software | "CVE-2021-44228 — Log4Shell" |
| **CWE** | the *kinds* of mistakes that cause them | "CWE-502 — trusting data you shouldn't" |
| **CAPEC** | the *tricks* attackers use to abuse those mistakes | "CAPEC-586 — object injection" |
| **ATT&CK** | the *moves* real attackers actually perform | "T1055 — process injection" |
| **D3FEND** | the *defences* that stop those moves | "D3-NTA — network traffic analysis" |

Each encyclopedia says "see also…" about the others, but they use different
words, different spellings, and sometimes they say the *same* thing twice from
two directions.

**This folder is the machine that puts all five encyclopedias into one giant
map**, where every card is a dot and every "see also" is an arrow. The map lives
in a database called **Neo4j**, and once it's built you can walk from a real
broken thing all the way to the defence that stops it, in five steps:

```
CVE  →  CWE  →  CAPEC  →  ATT&CK  →  D3FEND
bug     mistake  trick     move       defence
```

That five-step walk is the whole reason this project exists. When the loader
finished, **81,625 real CVEs could walk that whole path**, reaching **124
different defences**.

---

## 2. Where the cards come from, where they go

```
data-preprocessing/          ← someone else already cut the cards
   CVE/*.json   (≈ 1 GB!)         and made them all the same shape
   CWE/*.json
   CAPEC/*.json
   mitre-attack/*.json
   mitre-defend/*.json
          │
          ▼
     data-loading/           ← YOU ARE HERE. The machine.
          │
          ▼
     Neo4j (in Docker)       ← the finished map
   1,107,173 dots
   1,129,919 arrows
```

Two kinds of card, and **only** two kinds. This matters — it's why the machine is
simple:

- an **entity card** ("a thing"): it has an `id` and a `type`. → becomes a **dot**
- an **edge card** ("a connection"): it has a `type` and *two* ids, a from and a
  to. → becomes an **arrow**

The machine genuinely doesn't care whether a dot is a vulnerability or a
sandwich.

---

## 3. Two toy boxes, and one unbreakable rule

The folder is split into two packages, and this split *is* the design:

**Box 1 — `graphload/` — "the machine"**
A general-purpose graph loader. It knows about dots and arrows and nothing else.
Search it for the word "CVE" or "cyber" and you get **zero hits**. You could
point it at a library catalogue or a recipe book.

**Box 2 — `catalog/` — "the instructions for this particular job"**
Almost no logic here at all — just *lists*. Which files exist, what to call
things, which duplicates to squash, what to compute afterwards.

The rule:

```
catalog/  ──may import──▶  graphload/
catalog/  ◀──NEVER────     graphload/
```

And it's not an honour system. `py main.py --self-check` literally reads every
engine file looking for `import catalog`, and fails the build if it finds one
(`main.py:75-95`). If the machine ever *needs* to know about cybersecurity, that
means the design sprang a leak — fix the design, don't add the import.

Why care? Because "add a sixth encyclopedia" should mean writing a new list, not
editing the machine.

---

## 4. The buttons (how you run it)

```bash
py -m pip install -r requirements.txt        # 1. two libraries: neo4j, ijson
docker compose --env-file ../.env up -d      # 2. start the database
py main.py --check                           # 3. "hello? anyone there?"
py main.py                                   # 4. GO
```

Every button on the machine, from `main.py`:

| Button | What it does |
|---|---|
| `--check` | ask the database "are you alive, and what's in you?" — takes 1 second |
| `--self-check` | prove the machine doesn't peek at the instructions |
| `--dry-run` | do *everything* except actually writing. A rehearsal. |
| `--stage nodes edges` | run only some steps |
| `--only capec cwe` / `--skip cve` | work on only some encyclopedias |
| `--limit 500` | only read the first 500 cards per file — a fast trial |
| `--batch-size N` | how many cards per trip to the database (default 10,000) |
| `--no-cache` | forget the shortcut notes, re-read everything |
| `--allow-new-labels` | "I know there's a new kind of card, let it through and tell me its name" |

`--check` exists for a very human reason: it would be sad to spend twenty minutes
shovelling a gigabyte of JSON at a database that was never switched on.

---

## 5. The six steps, in order (and the order is *not* a preference)

`main.py` runs six stages. Each one needs the one before it. Think of building a
LEGO city.

### Step 1 — `constraints` (2 seconds) — *build the index of the phone book first*

Before any card goes in, the machine tells the database: "for each of the 32 kinds
of dot, `id` must be unique." Saying that automatically creates a **look-up
index** — like the alphabetical tabs on a filing cabinet.

**This is the single most important thing in the whole folder.** Here's why:

Later, 1.13 million arrows each have to find their two ends by id. That's **2.27
million searches**. With the index: instant, like flipping straight to "M" in a
phone book. Without it: read *every single one* of a million cards, 2.27 million
times over. **The same load goes from ~7 minutes to hours.**

There's an extra subtlety the code is careful about: Neo4j builds indexes in the
*background*, and a half-built index is ignored. So `stages/constraints.py` calls
`db.awaitIndexes()` and **waits**. Skipping that wait would silently buy you the
slow version anyway.

### Step 2 — `nodes` (182 seconds) — *put all the dots in*

Reads every entity file and writes a dot per card. It does **three** things in a
single pass through the files, because re-reading a gigabyte is the slowest thing
imaginable:

1. writes the dot,
2. remembers `id → (kind, which encyclopedia)` in the **registry** (Step 3 needs
   this),
3. saves that memory to disk (`.cache/registry-*.pickle`) so a future run can skip
   the reading entirely.

Result: **1,107,173 dots** — CWE 5,056 · CAPEC 1,538 · CVE 1,093,334 ·
ATT&CK 6,052 · D3FEND 1,193. (Yes: CVE is 96% of the graph. More on that later.)

### Step 3 — `edges` (94 seconds) — *the easy arrows*

Arrows where **both ends live in the same encyclopedia**. A CVE pointing at its
own severity score; a CWE category pointing at its own member. Safe, boring,
plentiful: **801,456 rows**.

### Step 4 — `bridges` (50 seconds) — *the hard, important arrows*

Arrows that **cross between encyclopedias** — CVE→CWE, CAPEC→CWE, CAPEC→ATT&CK,
D3FEND→ATT&CK. **334,040 rows**, 29% of everything, and *exactly* the path this
project exists to walk.

They're a separate step for two reasons, both forced by the data:

- They can't be drawn until **all** dots exist. A CAPEC card pointing at `T1055`
  is meaningless until ATT&CK is loaded. So this stage **ignores `--only`** and
  always reads every source — a subset would silently drop precisely the arrows
  that matter most.
- They're the ones that need the de-duplication rules (Step "one fact, one arrow"
  below).

Bonus: because it's separate, you can fiddle with `catalog/bridges.py` and re-run
*only* this stage — reshaping the 334,000 hardest arrows without touching the 1.1
million dots.

### Step 5 — `enrich` (89 seconds) — *stick the important sticker on the front*

Half the graph is severity data: 746,387 score cards dangling off 346,947 CVEs.
Nothing in the five-step walk goes through them — but "show me the *critical* CVEs
with a full trace to a defence" is a question you'd ask constantly, and it
shouldn't cost an extra hop every time.

So this step copies each CVE's headline score **onto the CVE dot itself**
(`cvss_base_score`, `cvss_base_severity`, `cvss_vector_string`, `cvss_version`)
while leaving all the detailed score dots in place.

Why afterwards, in the database, instead of in Python? Because the score files
don't say which CVE they belong to — that's in a *different* file. Rebuilding
that join in Python means holding two ~700,000-entry dictionaries in memory, on a
machine that's already tight. After loading, it's just a two-hop walk the index
already serves.

### Step 6 — `verify` (10 seconds) — *count everything and check it actually works*

Read-only. Counts dots per kind and arrows per kind, then asks four questions:

- **Dots with no `id`?** Must be 0. Anything else means the machine accidentally
  invented a dot. → **0** ✓
- **Lonely dots (no arrows at all)?** → **1,860**, all explained (see §11).
- **Any surviving `RELATED_TO`?** Must be 0 (see §9). → **0** ✓
- **Does the five-step walk actually work?** → **81,625 CVEs reach 124
  defences** ✓

That last check is the wise one. A graph can have every count perfectly right and
still fail to answer the one question it was built for.

---

## 6. Every single file, one line each

### Top level (4 files + docs)

| File | Job |
|---|---|
| `main.py` | The control panel. Parses the buttons, builds the shared `Context`, runs the six stages in order, times them, prints a pass/fail summary, writes the report. Also stops the run cold if validation finds something fatal — right after `nodes` and again after `bridges`. |
| `docker-compose.yml` | Starts Neo4j 5.26 in a container. 1536 MB heap, 768 MB page cache (sized to fit this machine's ~3.9 GB Docker VM), 60-minute transaction timeout for the enrich step, two persistent volumes so the graph survives a restart. Ports 7474 (web UI) and 7687 (Bolt, what Python speaks). |
| `queries.cypher` | ~20 starter questions in 7 friendly groups, with comments teaching you how to read Cypher. Starts with `CALL db.schema.visualization()` which literally *draws* the shape of the whole graph. |
| `requirements.txt` | Two lines. `neo4j` (the driver) and `ijson` (the streaming JSON reader). That's it. |
| `README.md` / `ARCHITECTURE.md` | The "why" and the file-by-file map. |

### `graphload/` — the machine (the parts that describe input)

| File | Job |
|---|---|
| `spec.py` | The vocabulary for describing a data source: `SourceSpec` (a folder), `EntityFile`, `EdgeFile`, and crucially `RecordShape`/`EdgeShape` — **which field holds the id is *declared*, not assumed.** The defaults (`id`, `type`, `relationship_type`, `source_ref`, `target_ref`) happen to match what preprocessing emits; data that calls them `uuid`/`kind`/`from`/`to` just passes a different shape instead of needing a different loader. Also `missing()`, which lists absent files so the run can fail helpfully. |
| `readers/__init__.py` | A tiny plug socket: name → function. Three plugs registered. |
| `readers/json_array.py` | **The reason the whole thing fits in memory.** Streams `[{…},{…}]` one record at a time with `ijson`. `CVE/vulnerabilities.json` is 249 MB and `cvss_v3_scores.json` is 236 MB — read all at once with plain `json.load`, the CVE folder alone balloons to ~4 GB of Python objects, on a machine whose Docker VM has 3.9 GB *total* and is already running a 1.5 GB Neo4j heap. Streamed, memory stays flat no matter how big the file is. |
| `readers/jsonl.py` | One JSON object per line. Reports the line number when a line is broken. |
| `readers/csv_rows.py` | CSV with a header. Everything arrives as text (CSV has no types); empty cells are dropped rather than stored as `""`. |
| `reading.py` | The middle-man: open a file, find each card's id, find its type, work out its label. Notice that `label_for` **records what it did** in `Findings` rather than deciding what to do about it — the stage decides policy. Also `scan_entities`, the cheap "ids only" pass used when rebuilding the registry. |

### `graphload/` — naming and shaping

| File | Job |
|---|---|
| `naming.py` | Three mechanical translations: `attack-technique` → `AttackTechnique` (dot kinds), `subtechnique-of` → `SUBTECHNIQUE_OF` (arrow kinds), `x_mitre_platforms` → `platforms` (field names). Plus `assert_identifier` — the safety valve. Labels can't be sent to the database as parameters; they have to be pasted into the query text. So every one is checked against a strict pattern first, and a typo fails loudly here rather than building a weird query. |
| `transform.py` | Card → properties. Lifts `id`/`type` out (the type *became* the label, so keeping it invites the two disagreeing), strips prefixes, and **refuses nested values**: Neo4j properties hold a single value or a flat list, never a nested map. Without this check, the failure would be a cryptic driver error 300,000 records in; with it, you get the offending record and field named. `Collisions` gathers every "two fields would collapse onto one name" case so they're all reported at once instead of one per run. |

### `graphload/` — talking to the database

| File | Job |
|---|---|
| `config.py` | Reads `NEO4J_URI`/`USER`/`PASSWORD`/`DATABASE` from the repo-root `.env`. No dotenv library — it's four `KEY=value` lines. A real environment variable always beats the file, so `NEO4J_URI=… py main.py` works for a one-off. `repo_root()` walks *up from this file* rather than trusting the current directory, which is why you can run the loader from anywhere. |
| `driver.py` | Connect, and `check()` — "reachable? credentials right? what's already in there?" in one second. Turns an auth failure or a dead container into a readable sentence (including the exact `docker compose` command to fix it) instead of a stack trace. |
| `schema.py` | Creates the uniqueness constraints and waits for the indexes. The constraint does double duty: it's the speed thing *and* the backstop that makes it impossible for two cards to quietly fuse into one dot by sharing an id. |
| `batch.py` | How writes actually happen. Two extremes to avoid: one query per card = a network round-trip per card (hours), and one query for everything = a single transaction holding 1.1M dots in a 1.5 GB heap (crash). The middle is `UNWIND $rows AS row` — one trip per few thousand cards, rows travelling as a single parameter. Values are **always** parameters, so nothing in the data can rewrite the query. Also contains `GroupedWriter` (see §7). |

### `graphload/` — resolving and routing

| File | Job |
|---|---|
| `registry.py` | The giant address book: `id → (kind, encyclopedia)` for all 1.1M ids. Three separate parts need it, so it's built once. **Memory trick:** kind and encyclopedia are *interned* into a small table and each id maps to a single small integer, not to a pair of strings. Also the per-source cache, fingerprinted by each file's (path, size, mtime) — touch one file in one source and only *that* source is re-read. Duplicate ids are *collected*, not raised, so all of them get reported together. |
| `router.py` | Per arrow: does it stay inside one encyclopedia (**local**), cross between two (**bridge**), or point at nothing (**dangling**)? **Decided by the endpoints, never by the filename** — and the data insists on this: `mitre-defend/relationships.json` is one file, but only **1,310** of its 6,471 rows are D3FEND-to-D3FEND. 3,544 point at ATT&CK, 1,103 live entirely inside CWE's ids, 482 come *from* ATT&CK, 32 run CWE→D3FEND. Nothing in the filename says so; only the ends do. |
| `dedupe.py` | The "one fact, one arrow" machinery. A `CanonicalRule` says "all these input shapes are the same fact"; matching rows get rewritten to one canonical direction and given a **deterministic** id (`uuid5` from type+ends), so every copy lands on the *same* arrow no matter which file or which stage it came from. `split_union_values` prepares the properties that should *accumulate* rather than overwrite. |

### `graphload/` — checking and reporting

| File | Job |
|---|---|
| `validate.py` | The gates (§8). `Findings` collects every problem; `fatal()` decides which ones stop the run and `warnings()` which ones merely get mentioned. |
| `report.py` | Writes `.cache/load_report.json`: timings, warnings, per-stage results, per-label and per-type counts, plus which Python and OS produced it. Made to be **diffed** after a re-crawl — much better than scrolling back through terminal output. |
| `context.py` | One object holding everything a stage needs, assembled once, so no stage ever reaches for a global. It holds **both** `all_specs` and `selected_specs` on purpose: dots and local arrows honour your `--only`, but the registry and the bridges stage need *every* source. |
| `enrichment.py` | An 18-line dataclass: `EnrichmentStep(name, description, cypher)`. Keeping post-load passes as *data* is why adding one touches no stage. |

### `graphload/stages/` — the six steps

| File | Job |
|---|---|
| `__init__.py` | The `ORDER` tuple (the dependency chain) and the name → module map. |
| `constraints.py` | Step 1. Builds constraints from the *declared* label list, not from the data — so indexes exist before a single card is read. Idempotent (`IF NOT EXISTS`), so re-running is free. |
| `nodes.py` | Step 2. The one-pass write + registry-fill + cache-save described above. Also the guard that refuses to load if a card already has a field named `catalog` (§9). |
| `edges.py` | Step 3. Twenty lines: ensure the registry, then load arrows where `Route.LOCAL`. |
| `bridges.py` | Step 4. Same, but `Route.BRIDGE`, and always over **all** sources. |
| `_edges.py` | The shared engine both edge stages use — they differ in exactly one thing (which `Route` they accept), so everything else lives here. Two orderings matter: de-duplication happens **before** name conversion (the rules match the source's own vocabulary like `related-to`), and union properties are chosen **after** it (the rule that matched is what decides which properties accumulate). Also stamps `asserted_by` on every arrow. |
| `_registry.py` | If you ran `--stage bridges` alone, nobody filled the address book — so this fills in every un-loaded source from its pickle (or rescans if the cache is stale). This is why per-source caching matters: 1.1M ids resolve in a couple of seconds instead of re-streaming ~700 MB of CVE JSON. |
| `enrich.py` | Step 5. Runs the catalog's Cypher passes. Uses `session.run` rather than `execute_write` because `CALL {…} IN TRANSACTIONS` must be an autocommit transaction — that's the form that lets a pass over 346,947 dots commit in batches instead of one heap-exhausting transaction. |
| `verify.py` | Step 6. The counts and the four questions, including the real five-catalog traversal. |

### `catalog/` — the instructions (nothing but lists)

| File | Contains |
|---|---|
| `__init__.py` | Re-exports the seven things `main.py` needs. |
| `sources/__init__.py` | The list of five `SourceSpec`s. Adding a sixth is one line here plus one new module. |
| `sources/cve.py` | 7 files → 1,093,334 dots, 1,069,414 arrow rows. **96% of the graph.** Five entity files, four of which are severity rather than vulnerabilities. |
| `sources/cwe.py` | 10 files → 5,056 dots, 18,339 rows. Eight entity files because preprocessing pulled sub-records (platforms, mitigations, detection methods, consequences, introduction phases) out into shared dots, with the per-weakness commentary moved onto the arrows. |
| `sources/capec.py` | 6 files → 1,538 dots, 4,930 rows. Two edge files that load identically — the split is a fact about preprocessing, not about the graph. |
| `sources/mitre_attack.py` | 17 files → 6,052 dots, 36,346 rows. The widest variety of dot kinds: techniques, malware, tools, threat groups, campaigns, mitigations, tactics, matrices, analytics, detection strategies, data components, data sources, ICS assets, log sources. |
| `sources/mitre_defend.py` | 4 files → 1,193 dots, 6,471 rows. Smallest source, and the one whose arrows leave home the most — D3FEND deliberately keeps no local copy of a CWE or ATT&CK entry, it just points at their real ids. |
| `labels.py` | All 32 `type` → label mappings, plus `all_labels()` (the set the constraints are built from). |
| `properties.py` | The `PropertyPolicy`: which prefixes to strip, which fields to drop from dots and from arrows, and the name of the provenance property. |
| `bridges.py` | The 8 `CanonicalRule`s, with measured counts in the comments. Plus `REL_TYPE_OVERRIDES`, which is **empty** — every arrow name in the dataset translates cleanly. |
| `enrichments.py` | The 8 CVSS passes, generated from one preference-ordered tuple. |

### `.cache/` — the machine's own scribbles (gitignored)

| File | What it is |
|---|---|
| `registry-cve.pickle` | 53 MB — the CVE address book, so it never has to be rebuilt |
| `registry-cwe/capec/mitre-attack/mitre-defend.pickle` | the same, per source (33 KB – 232 KB each) |
| `load_report.json` | the machine-readable record of the last run |
| `load.log` | the saved terminal output of the last full run |

---

## 7. The four clever tricks

**1. Streaming (don't hold the whole file).** Covered above: `ijson`, flat memory,
1 GB of JSON read with megabytes of RAM.

**2. Grouped flushing (the trick streaming alone can't solve).** Arrows can't be
written one at a time — they must be **grouped** by `(from-kind, arrow-kind,
to-kind)`, because that triple is what fixes the query text. But collecting all
1.13M rows first would cost more memory than the entire Neo4j heap. So
`GroupedWriter` keeps a small bucket per group, flushes a bucket the moment it
fills a batch, and if total buffering ever crosses a ceiling (50,000 rows) it
flushes the **biggest** bucket early. One pass through the file, bounded memory,
any number of groups. Grouping has a second payoff: each batch's endpoint
look-ups hit exactly two indexes.

**3. Union-on-write (let the database do the merging).** When two encyclopedias
assert the same fact, the second write must not erase the first's provenance.
Doing that in Python means holding 334,000 arrows in a dictionary. Instead the
query itself unions:

```cypher
SET r.asserted_by = [x IN coalesce(r.asserted_by, []) WHERE NOT x IN row.u['asserted_by']]
                    + row.u['asserted_by']
```

Read it as: "keep what's already there minus anything I'm about to add, then add
mine." The `WHERE NOT x IN` guard is also exactly what makes a **re-run
idempotent** instead of appending the same provenance over and over.

**4. Per-source caching + interning.** The address book is cached per
encyclopedia and fingerprinted by file size and mtime, and each id costs one
integer instead of two strings. That's what makes "add a sixth source" cheap and
"re-run one stage" fast.

---

## 8. The rules that stop bad data (and the one exception)

The machine **refuses to load** if any of these are true:

| Gate | Why it's fatal |
|---|---|
| A card has no `id` | nothing could ever point at it |
| A card has no `type` | there's no way to know what kind of dot it is |
| A `type` isn't in `labels.py` | **an invented label is how half a future ATT&CK release ends up filed under the wrong name.** `--allow-new-labels` downgrades this to a warning *and prints every name it derived*, so you can paste them in |
| **Two cards claim the same `id`** | the nastiest one. It doesn't error — the two would silently `MERGE` into one dot whose properties are a blend of two unrelated things, and **nothing downstream would ever look wrong** |
| Two fields collapse onto one name after prefix-stripping | one of them would vanish silently |
| A `related-to` shape has no bridge rule | see §9 — a surviving `RELATED_TO` is a modelling gap, not a cosmetic one |

`main.py` checks these twice: right after `nodes` (so a bad dataset stops
*before* arrows are written) and again after `bridges`.

**The one deliberate exception: dangling ends.** An arrow pointing at an id that
doesn't exist is **reported, counted, and skipped — never fatal, and never
invented as an empty dot.** There are exactly **4**, and they aren't a bug: CWE
cites four CVEs as observed examples that NVD either rejected or never published.

```
CWE-345  → CVE-2022-30267      CWE-362  → CVE-2014-8273
CWE-1233 → CVE-2014-8273       CWE-1421 → CVE-2019-1135
```

The right behaviour is to name them and decline to make them up. ✔

---

## 9. The naming decisions

### 32 dot kinds

A card's `type` becomes its label. **This isn't cosmetic:** 18 of the 32 type
values contain a hyphen, and `MATCH (t:attack-technique)` is a Cypher *syntax
error*. Without the mapping, every query against most of the graph would need
backticks forever.

Three of the mappings are genuine judgement calls, not translations:

- D3FEND's bare `technique`/`tactic` become **`DefensiveTechnique`/
  `DefensiveTactic`**, so nobody accidentally queries ATT&CK's by mistake.
- The **`x-mitre-` prefix is dropped** (`x-mitre-analytic` → `Analytic`) — it
  describes the file format, not the thing.
- **`Consequence` is shared on purpose** by CWE and CAPEC. They mean the same
  thing and preprocessing emits the same `{scope, impact}` shape for both.

(Related: preprocessing renames ATT&CK's STIX `attack-pattern`/`course-of-action`
to `attack-technique`/`attack-mitigation` because **CAPEC reuses those exact two
STIX type names for its own unrelated things** — left alone, two encyclopedias'
entities would merge under one label.)

### Arrow kinds

`UPPER_SNAKE`, derived mechanically. All **63 of D3FEND's artifact verbs stay
distinct** rather than being collapsed into one, faithful to how D3FEND defines
its ontology. `REL_TYPE_OVERRIDES` is empty because nothing needs a hand-written
name.

### Field names

`x_` marks a STIX custom extension — a fact about the *file*, not about the
thing. So it's stripped: `x_nvd_vuln_status` → `vuln_status`,
`x_capec_abstraction` → `abstraction`, `x_mitre_platforms` → `platforms`. A
collision after stripping is a **hard error**, not last-write-wins. (Verified:
none collide.)

Dropped: `type` from dots (it became the label), and
`type`/`relationship_type`/`source_ref`/`target_ref`/`source_name` from arrows
(all encoded in the arrow itself). Each arrow keeps its own `id`, which is the
deterministic uuid5 that makes a reload *update* it rather than add a second one.

### Why provenance is called `catalog`, not `source`

Every dot gets a property naming which encyclopedia it came from. It is
deliberately **not** called `source` — because CVSS and SSVC cards *already* have
a `source` field holding the assessing organisation (`nvd@nist.gov`, or a CNA
uuid). Taking that name would silently overwrite real data on **746,387 dots**.
`stages/nodes.py` refuses to load if a card already has a field by this name.

Arrows use `asserted_by` instead, and it's a **list**, because an arrow can
legitimately be claimed by two encyclopedias at once.

---

## 10. One fact, one arrow (the bridges)

Preprocessing leaves every cross-encyclopedia reference as one vague
`related-to`, disambiguated by a property — **328,883 rows, 29% of all arrows,
and exactly the path this project traverses.**

Worse, the encyclopedias assert the same fact from *both ends*: NVD says
`CVE-2021-44228 related-to CWE-502`, and CWE says the reverse. Loaded literally,
that's two vague arrows pointing opposite ways for one fact.

So **`RELATED_TO` does not exist in this graph.** In its place:

| Arrow | Direction | Forward | Reverse folded in |
|---|---|---|---|
| `HAS_WEAKNESS` | Vulnerability → Weakness | 308,742 (NVD) | 3,125 (CWE's observed examples) |
| `CLASSIFIED_AS` | Vulnerability → Category/View | 14,285 (NVD) | none exist |
| `EXPLOITS` | AttackPattern → Weakness | 1,212 (CAPEC) | 1,212 (CWE) |
| `MAPS_TO_TECHNIQUE` | AttackPattern → AttackTechnique | 271 (CAPEC) | 36 (ATT&CK) |

Two names were chosen very carefully:

- **`MAPS_TO_TECHNIQUE`**, not `USES`. MITRE publishes CAPEC's ATT&CK references
  as a taxonomy *correspondence* — "this pattern is the same idea as this
  technique" — not as an action someone performs.
- **`CLASSIFIED_AS`** exists because NVD doesn't only classify CVEs against
  weaknesses: **14,272 of its references point at a CWE *category* and 13 at a
  *view***, which are organisational groupings. Calling those `HAS_WEAKNESS`
  would assert something **false** about 14,285 arrows. (A CVE classified only at
  category level can still reach real weaknesses in two hops, via the category's
  own `HAS_MEMBER` arrows.)

Those eight shapes are **every** direction/label-pair combination `related-to`
appears in, checked exhaustively. `validate.py` refuses to load if a ninth ever
shows up.

### Three more same-fact collapses

| Arrow | The duplication | Fix |
|---|---|---|
| `CHILD_OF` between weaknesses | CWE **and** D3FEND both publish the CWE hierarchy — **1,079 of D3FEND's 1,103 rows are exact duplicates**, with 24 genuinely new. Separately, CWE records the same parent/child fact once per *view* (1,318 rows over 1,160 pairs) | `view_id`/`ordinal` become lists. Checked: only 2 of the 1,160 pairs have a differing `ordinal` |
| `HAS_LOG_SOURCE` | 3,165 rows over 1,001 pairs; the 351 repeats differ only in `channel` | `channel` becomes a list |
| `INTRODUCED_IN` | 1,398 rows over 1,373 pairs; the 25 repeats differ only in `note` | `note` becomes a list |

Each varies in exactly **one** attribute, so unioning is lossless.

### And two things deliberately left as parallel arrows

`COUNTERS` (293 repeated pairs) and `USES_DATA_COMPONENT` (57) also repeat their
endpoints — but they carry several **correlated** attributes. A `counters` arrow
explains *itself*: which artifact each side acts on, and how. Unioning each field
into its own list would destroy which value pairs with which. There, a repeated
pair is a genuinely second justification, so it stays a second arrow. **The
multiplicity is real, not accidental.**

### As actually loaded

| Type | Arrows | Rows in | Asserted by 2 catalogs |
|---|---|---|---|
| `HAS_WEAKNESS` | 310,924 | 311,863 | 931 |
| `CLASSIFIED_AS` | 14,285 | 14,285 | 0 (no reverse exists) |
| `COUNTERS` | 3,544 | 3,544 | 0 (parallel kept on purpose) |
| `CHILD_OF` (Weakness→Weakness) | 1,184 | 2,421 | 1,079 |
| `INTRODUCED_IN` | 1,373 | 1,398 | 0 |
| `EXPLOITS` | 1,212 | 2,424 | **1,212 — all of them** |
| `HAS_LOG_SOURCE` | 1,001 | 3,165 | 0 |
| `MAPS_TO_TECHNIQUE` | 307 | 307 | 0 |

Three lovely facts fall out of that table:

- **`EXPLOITS` is perfectly reciprocal** — every one of CAPEC's 1,212 weakness
  references is matched by the identical claim from CWE. Loaded literally that
  would have been 2,424 arrows for 1,212 facts.
- **`MAPS_TO_TECHNIQUE` is perfectly *non*-overlapping** — ATT&CK's 36 CAPEC
  references name pairs CAPEC doesn't assert. The two catalogs *disagree about
  what to cross-reference* rather than duplicating.
- **`CHILD_OF` lands on exactly 1,184** — CWE's 1,160 pairs plus D3FEND's 24 new
  ones. Confirmed by query, not inferred.

---

## 11. What the run actually produced (measured, not estimated)

From an empty database, Neo4j 5.26 community, 1536 MB heap / 768 MB page cache:

| | |
|---|---|
| **Dots** | **1,107,173** across 32 labels |
| **Arrows** | **1,129,919** across 96 types |
| Arrow rows written | 1,135,496 (801,456 local + 334,040 cross-source) |
| Rows that landed on an already-existing arrow | 5,577 |
| Rows matched by a canonical rule | 5,881 local + 329,982 cross-source |
| Dangling ends skipped | 4 |
| Dots with no `id` | 0 |
| Surviving `RELATED_TO` | 0 |
| **The full five-catalog trace** | **81,625 CVEs reach 124 defensive techniques** |
| Total time | **426 s** — constraints 2.2 · nodes 181.9 · edges 93.5 · bridges 49.9 · enrich 89.3 · verify 9.6 |

### Isolated dots: 1,860, every one accounted for

| Kind | Isolated | Why |
|---|---|---|
| `Vulnerability` | 1,548 | NVD hasn't analysed them yet — no CWE classification, no score |
| `DefensiveTechnique` | 122 | abstract parents in D3FEND's ontology, with no `counters` of their own |
| `AttackPattern` | 55 | CAPEC patterns with no CWE/ATT&CK mapping and no mitigation |
| `DataSource` | 42 | **all of them** — `data_source_ref` doesn't exist anywhere in this ATT&CK release, so the type is orphaned *upstream* |
| others | 93 | groupings with no members, leaves nothing references |

A sudden jump in this number is the cheapest possible signal that an edge file
failed to load — which is why `verify` prints it every run.

### Re-running is safe, and it's been proven

The latest `.cache/load_report.json` is a re-run of just `enrich` and `verify`.
All eight CVSS passes reported **0 properties set** — because every property was
already there. That's idempotency demonstrated, not claimed. Dots and arrows are
`MERGE`d on their ids for the same reason: a second run *updates* what changed and
adds what's new rather than duplicating anything. This is what makes it the thing
to run after the incremental crawler picks up new CVEs.

---

## 12. Known limits (already documented, not surprises)

1. **7 duplicate `Consequence` pairs across catalogs.** CWE contributes 311 and
   CAPEC 46, and 7 `(scope, impact)` pairs are byte-identical in both but get one
   dot each — the two preprocessors run independently and can't share an id
   space. README has the inspect-then-merge query.
2. **No affected-product data.** CPE applicability was dropped upstream (it's a
   nested AND/OR tree over 3.1M entries, not a flat list), so the graph can't
   answer "which software versions are affected".
3. **`asserted_by` list order is load order**, not a sort — compare with `size()`
   or `IN`, never by index.
4. **`COUNTERS`/`USES_DATA_COMPONENT` can be parallel arrows** (3,544 `COUNTERS`
   over 3,234 distinct pairs). Intentional — but a query counting *edges* rather
   than *distinct nodes* will count those pairs more than once.

---

## 13. Adding a sixth encyclopedia

If it takes more than this, the abstraction is wrong — which is the entire point
of the two-box split:

1. Write `catalog/sources/<name>.py` — one `SourceSpec` listing the folder and its
   files.
2. Add its `type` values to `catalog/labels.py`. (Or run
   `py main.py --dry-run --allow-new-labels --only <name>` and let it *tell you*
   every label it derived, then paste them in.)
3. Add bridge rules **only if** the new data cross-references existing sources.
4. `py main.py --only <name>` — additive; nothing else in the graph is touched.

Things you should **not** have to change, because they're declared rather than
assumed: different field names (pass a `RecordShape`/`EdgeShape`), a different
file format (`reader="jsonl"`/`"csv"`, or one new function in `readers/`), a new
prefix to strip (one entry in `properties.py`), a new post-load computation (one
`EnrichmentStep`).

And thanks to per-source caching, adding a sixth source re-scans only that
source — the other five load their address books from pickles in a couple of
seconds instead of re-streaming ~700 MB of CVE JSON.

---

## 14. Two tiny inconsistencies worth a one-line fix

Neither affects the graph; both are cosmetic:

1. **README's "rows collapsed onto an existing edge: 5,573".** The arithmetic from
   the actual run is 1,135,496 written − 1,129,919 arrows = **5,577**. Looks like
   the 4 dangling rows (which were read but never written) got subtracted twice.
2. **`stages/nodes.py`'s docstring says "Every node gets a `source` property".**
   The code is right — it uses `ctx.policy.source_property`, whose *value* is
   `catalog` — but the docstring wording is the one thing in the folder that
   contradicts the careful `catalog`-not-`source` explanation in
   `catalog/properties.py`.

Also worth knowing: `.cache/load.log` is from a run made **before**
`enrichments.py` was switched to the modern `CALL (v, s) { … }` form — that's why
it's full of deprecation warnings. The current code doesn't emit them (it needs
Neo4j 5.23+, and `docker-compose.yml` pins 5.26 LTS). And `data-loading/` is
currently **untracked in git** — it hasn't been committed yet.
