"""Making sure the registry covers every source, however the run was invoked.

`--stage nodes --only capec` populates the registry for CAPEC only, but CAPEC's
edges point at CWE and ATT&CK ids. So before any edge stage runs, the sources
that were not loaded in this run get filled in from their pickle cache -- or
scanned if the cache is missing or stale.

This is why the cache is per source rather than one file: `--stage bridges`
resolves every id in the graph in a couple of seconds instead of re-streaming
402 MB of CVE JSON.
"""

from __future__ import annotations

from ..context import Context
from ..reading import scan_entities
from ..registry import load_cached, save_cached


def ensure(ctx: Context) -> dict:
    filled, scanned = [], []
    for spec in ctx.all_specs:
        if spec.key in ctx.covered_sources:
            continue
        entries = (
            load_cached(ctx.settings.cache_dir, spec, ctx.repo_root) if ctx.use_cache else None
        )
        if entries is None:
            ctx.log(f"  scanning {spec.label} (no usable cache)")
            entries = scan_entities(spec, ctx.repo_root, ctx.label_overrides, ctx.findings)
            if ctx.use_cache:
                save_cached(ctx.settings.cache_dir, spec, ctx.repo_root, entries)
            scanned.append(spec.key)
        else:
            filled.append(spec.key)
        ctx.registry.extend(entries, spec.key)
        ctx.covered_sources.add(spec.key)

    ctx.sync_duplicates()
    if filled:
        ctx.log(f"  registry: {', '.join(filled)} from cache")
    ctx.log(
        f"  registry holds {len(ctx.registry):,} ids across {len(ctx.registry.labels())} label(s)"
    )
    return {"from_cache": filled, "rescanned": scanned, "ids": len(ctx.registry)}
