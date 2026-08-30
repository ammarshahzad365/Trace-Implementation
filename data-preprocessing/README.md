# Data Preprocessing (stage 2)

This folder turns the raw downloads from [`../data-acquisition/`](../data-acquisition/)
into flat JSON. There is one script per source, and each one is fully
independent: it reads its own raw data and writes its own two output files. No
state is shared between them.

| Folder | Script | Reads |
|---|---|---|
| [`CWE/`](CWE/README.md) | `cwe_preprocessing.py` | `data-acquisition/CWE/latest.json` |
| [`CAPEC/`](CAPEC/README.md) | `capec_preprocessing.py` | `data-acquisition/CAPEC/latest.json` |
| [`CVE/`](CVE/README.md) | `cve_preprocessing.py` | `data-acquisition/CVE/records/<year>/latest.json` |
| [`mitre-attack/`](mitre-attack/README.md) | `mitre_attack_preprocessing.py` | the three ATT&CK domain bundles |
| [`mitre-defend/`](mitre-defend/README.md) | `mitre_defend_preprocessing.py` | five of the six D3FEND domain files |

## Running

```
py main.py                       # run every script
py main.py --only cwe capec      # run just these
py main.py --skip mitre-defend   # run everything except this
```

`main.py` just runs each script in a subprocess, using the same Python
interpreter, and prints a pass/fail summary. Each script's output streams
straight through as it runs. The exit code is 0 only if every script that ran
exited 0.

Each script works out its own default `--input` and `--output-dir` from its own
file location, so the working directory doesn't matter. You can also run one
directly:

```
py CWE/cwe_preprocessing.py
```

## What comes out

Exactly 10 files - an `entities.json` and a `relationships.json` in each of the
five source folders. Four rules hold for all of them:

- **Nothing nests.** Every value is a single value or a list of single values -
  never a map, never a record inside a record. Every nested field in the source
  is either flattened, split out into its own records, or dropped; each source's
  README says which, and why.
- **Ids are readable.** `CVE-2021-44228`, `CWE-79`, `CAPEC-85`, `T1055` - not
  random ids. Where the source used a STIX id, it is kept alongside as `stix_id`.
- **Entities and links are separate files.** Inside each file, a record's own
  `type` field says what kind it is (`weakness`, `attack-technique`,
  `vulnerability`, ...), so nothing else is needed to tell the kinds apart.
- **Re-runs are byte-identical.** Generated ids are `uuid5` hashes of the
  record's own content, never random, so re-processing unchanged input produces
  an unchanged file.

Links that point at *another* catalog carry a `source_name` field. (D3FEND is
the exception, and its README explains why.)

## Text cleanup applied to everything

Every script ends with `clean_record()`, which runs over every entity and every
link on the way out, so no builder has to remember to tidy up after itself. Per
string it:

- normalizes line endings to LF (CRLF and lone CR both become LF)
- turns odd space characters - non-breaking spaces, tabs and other exotic
  spaces - into a plain space
- collapses runs of spaces, and trims each line
- collapses three or more newlines into a single blank line

Blank lines between paragraphs survive, because they carry meaning; the
indentation the source document was pretty-printed with does not. A string left
empty is dropped rather than written as `""`, and list values are deduplicated.

**Two things are deliberately left alone.** Markup that is quoted **content**
stays exactly as it is - XSS payloads, SOAP envelopes, C includes and
`<a>`/`<script>` samples appear inside these descriptions as the thing being
described, so stripping them would destroy the text. And a lone newline only
becomes a space where the source is known to hard-wrap its text; elsewhere it is
a real line break and is kept.

CWE, CAPEC and ATT&CK each have extra source-specific cleanup on top of this -
XHTML flattening, literal `"None"` strings, and so on. See their own READMEs.

## Where to read what

Each source's README explains **why** each field was kept, renamed, split out or
dropped, and lists the exact output counts per `type`. Start with the one for
the source you are working on.

`DATA_PROVENANCE_REPORT` covers all five at once from the other direction: every
entity type, every property and every relationship type in the output, with the
exact raw field each one came from and what happened to it on the way. Read it
when the question is *"where did this field come from?"* rather than *"how does
this source work?"*. Two formats, same subject:

- [`DATA_PROVENANCE_REPORT.docx`](DATA_PROVENANCE_REPORT.docx) - one numbered
  section per type (28 entity types, 39 relationship groups), each showing a real
  raw record, the same thing after preprocessing, and a field-by-field table of
  what changed. Editable in Word.
- [`DATA_PROVENANCE_REPORT.md`](DATA_PROVENANCE_REPORT.md) - the same ground
  organised by source rather than by type, for reading in git.
