"""HTTP API for adding records to the graph after the initial load.

Built on the same `graphload/` engine as the batch loader, so a record written
here is indistinguishable from one written by `main.py`: same labels, same
property names, same MERGE-on-id idempotency, same no-preprocessing rule.

See README.md in this folder.
"""
