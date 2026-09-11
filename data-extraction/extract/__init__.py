"""Turning unstructured text into graph records with an LLM.

`data-preprocessing/` parses files whose structure is already known. This package
handles the other half of TRACE: APT reports, repair notices and papers, where
nothing is known until a model reads the prose and says what is in it.

The output is the same shape `data-preprocessing/` produces and `ingest/` writes
-- entity and relationship dicts -- so nothing downstream needs to know a model
was involved. `ingest/writer.py` is the only writer, here as everywhere else.

Read `README.md` next to this file for how to run it; the module docstrings
explain why each stage exists and which part of the paper it comes from.
"""
