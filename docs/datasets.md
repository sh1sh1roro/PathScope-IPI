# Evaluation datasets

| Collection | Traces | Repository material |
| --- | ---: | --- |
| RQ1 | 660 | [Aggregate Tables 1–3](../data/rq1/) |
| RQ2 comparison | 628 | [Manifest](../data/rq2/manifest.csv) rows with a non-empty `main_group` |
| RQ2 module ablation | 540 | Manifest rows with `ablation_540=true` |
| C annotation and blind review | 748 | All manifest rows |

The RQ1 paired sample contains 108 InjecAgent, 74 Conversational Attack, and 104 Important Instructions pairs. The RQ2 comparison contains 240, 180, and 208 traces from these families, respectively. The ablation uses 120 traces each from `A0`, `A1`, and `A2` and 90 each from `MT0` and `MT1`.

| Paper group | Archived identifier | Attack family |
| --- | --- | --- |
| IA-0 / IA-1 | `A0` / `A2` | InjecAgent |
| CA-0 / CA-1 | `MT0` / `MT1` | Conversational Attack |
| IMP-0 / IMP-1 | `IMP0` / `IMP1` | Important Instructions |

Historical `A1` is the intermediate configuration included in the ablation. Each RQ2 trace carries a `source_sha256` identifying its source version. RQ1 and RQ2 use different CA-1 run collections.

The C archive contains 707 determinate references and 41 Unknown references. [Blind-review decisions and the 19 human adjudications](../data/rq2/annotation/) are recorded separately. For C and G, Accuracy uses the corresponding known references as its denominator. A prediction of Unknown on a known reference counts as incorrect. Coverage is the share of known references with a determinate prediction. Macro-F1 is the mean of the True- and False-class F1 scores.
