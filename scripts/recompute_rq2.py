"""Recompute paper Tables 4 and 5 from the frozen public RQ2 artifact.

No third-party packages, model calls, or tool execution are used.
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
DATA = REPO / "data" / "rq2"
KNOWN = ("true", "false")
MAIN = ("Tool-Name Match", "Full PathScope")
ABLATION = ("Full PathScope", "w/o TRPV", "w/o GCES")
GROUPS = ("InjecAgent", "Conversational Attack", "Important Instructions")


def load(name: str) -> list[dict[str, str]]:
    with (DATA / name).open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def index(rows, key):
    indexed = {}
    for row in rows:
        value = key(row)
        if value in indexed:
            raise ValueError(f"Duplicate record: {value}")
        indexed[value] = row
    return indexed


def save(path: Path, rows: list[dict]) -> None:
    with path.open("x", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def metrics(group, method, dim, ids, labels, predictions):
    matrix = Counter(
        (labels[tid][dim], predictions[tid, method][dim])
        for tid in ids
        if labels[tid][dim] in KNOWN
    )
    denominator = sum(matrix.values())
    correct = sum(matrix[c, c] for c in KNOWN)
    unknown = sum(matrix[c, "unknown"] for c in KNOWN)
    f1 = []
    for label in KNOWN:
        size = sum(n * ((a == label) + (b == label)) for (a, b), n in matrix.items())
        f1.append(2 * matrix[label, label] / size if size else 0)
    return dict(
        scope=group,
        method=method,
        dimension=dim,
        total=len(ids),
        reference_known=denominator,
        reference_unknown=len(ids) - denominator,
        correct=correct,
        prediction_covered=denominator - unknown,
        prediction_unknown=unknown,
        coverage=(denominator - unknown) / denominator,
        accuracy=correct / denominator,
        macro_f1=sum(f1) / 2,
    ), matrix


def error_type(reference, prediction):
    if prediction == reference:
        return "correct"
    if prediction == "unknown":
        return "abstain"
    return "false_positive" if prediction == "true" else "false_negative"


def run(output: Path) -> None:
    traces = index(load("manifest.csv"), lambda r: r["trace_id"])
    labels = index(load("annotation/reference_labels.csv"), lambda r: r["trace_id"])
    predictions = index(load("predictions/predictions.csv"), lambda r: (r["trace_id"], r["method"]))
    assert len(traces) == 748 and traces.keys() == labels.keys()

    main = {g: sorted(t for t, r in traces.items() if r["main_group"] == g) for g in GROUPS}
    ablation = sorted(t for t, r in traces.items() if r["ablation_540"] == "true")
    assert [len(main[g]) for g in GROUPS] == [240, 180, 208]
    assert len(ablation) == 540

    required = {(t, m) for ids in main.values() for t in ids for m in MAIN}
    required |= {(t, m) for t in ablation for m in ABLATION}
    assert predictions.keys() == required, "Frozen prediction set does not match table scopes"
    for tid, method in required:
        assert predictions[tid, method]["source_sha256"] == traces[tid]["source_sha256"]
        assert labels[tid]["source_sha256"] == traces[tid]["source_sha256"]
        assert all(predictions[tid, method][d] in (*KNOWN, "unknown") for d in "CG")
        assert all(labels[tid][d] in (*KNOWN, "unknown") for d in "PCEG")

    table4, table5, a2, a3, a4 = [], [], [], [], []
    for group, ids in main.items():
        for method in MAIN:
            for dim in "CG":
                row, matrix = metrics(group, method, dim, ids, labels, predictions)
                table4.append(row)
                if method == "Full PathScope":
                    a3.append(dict(
                        scope=group,
                        dimension=dim,
                        reference_known=row["reference_known"],
                        TP=matrix["true", "true"],
                        TN=matrix["false", "false"],
                        FP=matrix["false", "true"],
                        FN=matrix["true", "false"],
                        true_pred_unknown=matrix["true", "unknown"],
                        false_pred_unknown=matrix["false", "unknown"],
                        prediction_unknown=row["prediction_unknown"],
                    ))

    transitions = Counter()
    for method in ABLATION:
        for dim in "CG":
            row, _ = metrics("Ablation 540", method, dim, ablation, labels, predictions)
            base, _ = metrics("Ablation 540", "Full PathScope", dim, ablation, labels, predictions)
            row["accuracy_delta_pp"] = 100 * (row["accuracy"] - base["accuracy"])
            row["macro_f1_delta_pp"] = 100 * (row["macro_f1"] - base["macro_f1"])
            table5.append(row)
            if method == "Full PathScope":
                continue
            for tid in ablation:
                reference = labels[tid][dim]
                if reference not in KNOWN:
                    continue
                full = predictions[tid, "Full PathScope"][dim]
                reduced = predictions[tid, method][dim]
                full_error = error_type(reference, full)
                reduced_error = error_type(reference, reduced)
                transition = ("correct" if full_error == "correct" else "wrong") + "_to_" + (
                    "correct" if reduced_error == "correct" else "wrong"
                )
                transitions[method, dim, transition, full_error, reduced_error] += 1
                a4.append(dict(
                    method=method,
                    dimension=dim,
                    trace_id=tid,
                    experiment_arm=traces[tid]["experiment_arm"],
                    reference=reference,
                    full_prediction=full,
                    ablated_prediction=reduced,
                    transition=transition,
                    full_error=full_error,
                    ablated_error=reduced_error,
                    source_sha256=traces[tid]["source_sha256"],
                ))

    scopes = {
        "Paper Table 4 (628)": sorted({t for ids in main.values() for t in ids}),
        "Paper Table 5 (540)": ablation,
        **main,
    }
    for scope, ids in scopes.items():
        for dim in "PCEG":
            counts = Counter(labels[t][dim] for t in ids)
            a2.append(dict(
                scope=scope,
                dimension=dim,
                total=len(ids),
                true=counts["true"],
                false=counts["false"],
                unknown=counts["unknown"],
                derived_important_pe=sum(
                    labels[t]["pe_source"] == "execution_chain_protocol_from_archived_events"
                    for t in ids
                ) if dim in "PE" else 0,
            ))

    output.mkdir(parents=True, exist_ok=False)
    files = {
        "paper_table4_diagnosis.csv": table4,
        "paper_table5_ablation.csv": table5,
        "appendix_a2_label_distribution.csv": a2,
        "appendix_a3_confusion.csv": a3,
        "appendix_a4_ablation_trace_details.csv": a4,
        "appendix_a4_transition_counts.csv": [
            dict(method=m, dimension=d, transition=t, full_error=f, ablated_error=a, count=n)
            for (m, d, t, f, a), n in sorted(transitions.items())
        ],
    }
    for name, rows in files.items():
        save(output / name, rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("recomputed_tables"))
    args = parser.parse_args()
    run(args.output)


if __name__ == "__main__":
    main()

