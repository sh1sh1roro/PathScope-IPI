# Offline diagnosis

[PathScope's diagnostic module](../src/pathscope_modular_v2.py) exposes `diagnose_packet(packet, config)`. An evidence packet supplies trace identity, task-specific tool and argument constraints, structured execution events with provenance, and the terminal status. The released [structural event extract](../data/rq2/evidence/tool_events.jsonl) documents tool records and their links. The table scripts score the [archived predictions](../data/rq2/predictions/predictions.csv).

| Configuration | `ModuleConfig` settings |
| --- | --- |
| Full PathScope | Defaults |
| w/o TRPV | `m1_execution_chain_linking=False, m2_parameter_verification=False` |
| w/o GCES | `m3_stage_completeness=False, m4_evidence_sufficiency=False` |

TRPV links proposals, invocations, and results and checks invocation arguments. GCES evaluates the required stages and evidence sufficiency. `diagnose_packet` maps the diagnosis category to C and G, then applies the evidence-sufficiency rule. For example, `parameter_mismatch` maps to C=True and G=False before that rule is applied. Stage evaluation groups candidate chains by tool name. The [C reference annotation protocol](../data/rq2/annotation/c_annotation_protocol.md) uses distinct linked chains in the required order.

Tool-Name Match uses the names of proposed tools to provide the RQ2 baseline. Its predictions use the `Tool-Name Match` identifier in the prediction table.
