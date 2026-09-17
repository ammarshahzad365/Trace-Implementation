"""Sweep the alignment threshold and report P/R/F1 at each step.

    py -m extract.eval.calibrate                      # embedding only, fast
    py -m extract.eval.calibrate --judge              # with the LLM judge, slow
    py -m extract.eval.calibrate --embed-model qwen3-embedding:8b

Section 5.2.2 says theta was set to 0.9 "after fine-tuning". This is that
fine-tuning, done in the open: for every threshold from 0.30 to 0.98, how many
gold entities align to the right node, to a wrong node, or to nothing. The
output is the curve to put in the report, with the paper's 0.9 marked on it.

## The gold set

`gold/alignment.jsonl`, one entity per line:

    {"type": "group", "name": "Hafnium", "description": "...", "expected_id": "G0125"}
    {"type": "tool",  "name": "OrpaCrab", "description": "...", "expected_id": null}

`expected_id: null` means the entity is genuinely new -- nothing in the graph
should match. Getting those right is half the score: a threshold low enough to
catch every true match will also merge new things into unrelated nodes, and
that is the worse failure.

## Two modes

Embedding-only takes the top-1 candidate above theta as the match. It is fast
and shows the embedder's ceiling. `--judge` runs the full pipeline -- the LLM
picks among everything above theta or declines -- which is what production
does, and is the number to report. The gap between the two is the judge's
contribution.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from extract import graph, llm, ontology, prompts  # noqa: E402
from extract.align import embedding_text  # noqa: E402
from extract.config import settings  # noqa: E402

GOLD = Path(__file__).resolve().parent / "gold" / "alignment.jsonl"
STEPS = [round(0.30 + 0.02 * i, 2) for i in range(35)]  # 0.30 .. 0.98


def load_gold(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            rows.append(json.loads(line))
    return rows


def retrieve(cfg, handle, rows: list[dict]) -> list[list[dict]]:
    """Top-20 same-type candidates for every gold entity, fetched once."""
    texts = [embedding_text(row["name"], row.get("description", "")) for row in rows]
    vectors = llm.embed(cfg, texts)
    out = []
    for row, vector in zip(rows, vectors):
        merged = sorted(
            (hit for label in ontology.align_labels(ontology.normalise_type(row["type"]) or row["type"])
             for hit in graph.similar(handle, label, vector, k=20)),
            key=lambda hit: hit["cosine"], reverse=True,
        )[:20]
        out.append(merged)
    return out


def judge(cfg, row: dict, above: list[dict]) -> str | None:
    system, user = prompts.alignment_prompt(
        name=row["name"],
        entity_type=row["type"],
        description=row.get("description", ""),
        candidates=above,
    )
    answer = llm.chat_json(
        cfg, system=system, user=user, schema=prompts.alignment_schema([c["id"] for c in above])
    )
    return answer.get("match_id") or None


def score(rows: list[dict], nearby: list[list[dict]], theta: float, cfg, use_judge: bool) -> dict:
    tp = fp = fn = tn = 0
    for row, candidates in zip(rows, nearby):
        expected = row.get("expected_id")
        above = [c for c in candidates if c["cosine"] >= theta]
        if not above:
            chosen = None
        elif use_judge:
            chosen = judge(cfg, row, above)
        else:
            chosen = above[0]["id"]

        if expected and chosen == expected:
            tp += 1
        elif expected and chosen != expected:
            fn += 1
            if chosen:
                fp += 1  # matched, but to the wrong node: counts against precision too
        elif not expected and chosen:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"theta": theta, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": precision, "recall": recall, "f1": f1}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--gold", type=Path, default=GOLD)
    parser.add_argument("--embed-model", help="override EMBED_MODEL for this run")
    parser.add_argument("--judge", action="store_true", help="run the LLM judge above theta")
    parser.add_argument("--steps", help="comma-separated thetas instead of the default sweep")
    args = parser.parse_args(argv)

    cfg = settings()
    if args.embed_model:
        from dataclasses import replace
        cfg = replace(cfg, embed_model=args.embed_model)

    rows = load_gold(args.gold)
    if not rows:
        raise SystemExit(f"{args.gold} is empty")
    steps = [float(s) for s in args.steps.split(",")] if args.steps else STEPS

    print(f"embedder: {cfg.embed_model}   judge: {'on (' + cfg.extract_model + ')' if args.judge else 'off'}")
    print(f"gold: {len(rows)} entities, {sum(1 for r in rows if r.get('expected_id'))} with a true match\n")

    with graph.session(cfg) as handle:
        nearby = retrieve(cfg, handle, rows)

    print("per-entity: best candidate and whether it is the expected one")
    for row, candidates in zip(rows, nearby):
        best = candidates[0] if candidates else None
        expected = row.get("expected_id")
        rank = next((i + 1 for i, c in enumerate(candidates) if c["id"] == expected), None)
        mark = "ok " if best and best["id"] == expected else ("new" if not expected and best else "MISS")
        print(f"  {mark}  {row['type']:16} {row['name']:28} expected={expected or 'new':10} "
              f"best={best['name'] if best else '-':28} cos={best['cosine'] if best else 0:.3f}"
              f"{'' if rank in (None, 1) else f'   (expected at rank {rank})'}")

    print(f"\n{'theta':>6} {'P':>6} {'R':>6} {'F1':>6}   tp fp fn tn")
    best = None
    for theta in steps:
        result = score(rows, nearby, theta, cfg, args.judge)
        flag = "  <- paper" if abs(theta - 0.9) < 1e-9 else ""
        print(f"{theta:6.2f} {result['precision']:6.2f} {result['recall']:6.2f} {result['f1']:6.2f}   "
              f"{result['tp']:2} {result['fp']:2} {result['fn']:2} {result['tn']:2}{flag}")
        if best is None or result["f1"] > best["f1"]:
            best = result
    print(f"\nbest F1 {best['f1']:.2f} at theta = {best['theta']:.2f}   "
          f"(paper: 0.90; set ALIGN_THRESHOLD accordingly and report both)")
    graph.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
