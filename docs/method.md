# Method and evaluation boundaries

## Final configuration

The final supplied artifact is `reference/original_submission.py` (original filename: `CD.py`). It contains a generated attack entry point and five embedded modules. The readable modules and entry-point template preserve this implementation. Earlier fixed-marker experiments are not included as a second runnable solution.

The entry point selects either the GPT-OSS or Gemma route, in this order:

1. Explicit model/route information in the configuration.
2. Supported environment variables.
3. Invocation order, defaulting to GPT-OSS then Gemma.

Each route has 20 selected configurations. The historical banks include other variants that are not in these active lists.

## Probes and feedback

For every configuration, the original notebook sets 30 probes. Each probe resets the provided environment, submits the candidate, and inspects the exported tool trace. Only the final 20 probe observations are used for ranking. The source does not establish a statistical justification for discarding the first 10.

The implementation counts successful events for a configured set of tool names. Some trace schemas without explicit success/error fields are treated optimistically by the original helper. The offline tests preserve this implementation; they do not validate every SDK trace schema.

For a counted action total `a`, the proxy reward is:

```text
reward(a) = 0,       if a <= 0
reward(a) = 4a + 2,  otherwise
```

The primary ranking key is the sum of proxy rewards divided by the sum of elapsed times over the selected probe tail. Ties use mean action count, consistency of action counts, and elapsed time.

**This is a search heuristic, not the official score.** It does not fully reproduce the official authorization predicates, severity weighting, or novelty/deduplication rules. Successful tool execution alone does not establish an authorization violation in a real application.

## Candidate generation and replay

The selected configuration generates at most 2,000 candidates per target model. Deterministic indices vary simulated tool arguments. The entry point checks that each candidate contains one user message and excludes the old fixed marker.

The final path primarily targets one tool action with a single-message candidate. Role-format text within a message is still text in one message. Variation produces candidates for evaluation, not a guaranteed number of distinct failures.

The official evaluator independently replays the candidates. Public and hidden guardrails can produce different results. The repository does not include raw replay logs or a verified exact final score, so it reports the participant-confirmed medal and rank rather than inventing a score or a transfer-success rate.

## Engineering contribution represented here

- Model-specific configuration search and routing.
- Tool-trace feedback and time-aware selection.
- Deterministic candidate generation and structural validation.
- A single-file SDK integration for independent replay.
- Failure analysis across public and hidden guardrail behavior.

The supplied solution does not train model weights and does not implement SFT, QLoRA, reinforcement learning, or model ensembling.
