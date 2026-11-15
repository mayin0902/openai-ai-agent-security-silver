# Reproduction and provenance

## What is preserved

`reference/original_submission.py` is a byte-for-byte copy of the supplied `CD.py`. Its SHA-256 and the hashes of the extracted modules are recorded in `reference/provenance.json`. Extraction uses Python's AST and literal evaluation; it does not execute the original notebook-style script.

The build combines `submission/attack_template.py` and the five readable files in `src/attacks/`. A regression check compares the resulting source **byte-for-byte** with the `attack_code` string in the original artifact. Changes to build tooling should preserve this check. Intentional algorithm changes require a separate experiment and corresponding provenance updates.

The repository adds documentation, build tooling, a Kaggle launcher, and offline checks. It does not include official SDK code, target-model weights, private guardrails, original replay logs, or the competition PDFs and personal résumé documents.

## Local checks

```bash
python scripts/build_submission.py
python -m unittest discover -s tests -v
```

These commands require Python 3.11+ and no third-party packages. They run on CPU and do not contact a model or external tool service.

The test double implements only the small SDK interfaces needed to construct candidates. It exists exclusively inside the test process. Passing tests demonstrate source preservation, active-profile construction, routing behavior, and specific trace/ranking helpers—not official SDK compatibility or leaderboard reproduction.

## Notebook settings versus bare-module defaults

The original notebook sets environment variables **before importing** its generated module. Loading `dist/attack.py` by itself uses different fallback values for the probe budget.

| Setting | Original notebook / launcher | Bare generated module fallback |
| --- | --- | --- |
| GPT candidates | 2,000 | 2,000 |
| Gemma candidates | 2,000 | 2,000 |
| Probes per configuration | 30 | 3 |
| Probe tail used for ranking | 20 | 2 |
| Maximum tool hops | 8 | 8 |

`scripts/run_kaggle.py` applies `configs/competition.json` before importing the module. Merely building the file does not set runtime environment variables.

## Official runtime

1. Use the competition-provided Kaggle notebook and attach its SDK, evaluator, and model resources.
2. Place this repository in the notebook environment and change to its root directory.
3. Run `python scripts/run_kaggle.py`.

The launcher locates `aicomp_sdk` and `kaggle_evaluation` beneath `/kaggle/input`, builds `/kaggle/working/attack.py`, runs candidate-only checks with the installed SDK, writes the original placeholder CSV, and starts `JEDAttackInferenceServer`. It is intentionally restricted to the Kaggle layout and rejects the author's login-only compute host.

The server import path is retained from the supplied artifact. If the official SDK or evaluator has changed, use the matching competition environment rather than assuming that a newer SDK behaves identically. No real-SDK or model evaluation was performed during this repository organization.

The `submission.csv` zero values are required placeholder data in the original workflow, not measured scores. Do not use them to infer a failed or successful evaluation.

## Team result

The participant confirmed **Silver, 58 / 4,186 teams**, with participation during June–September 2026. The percentage is computed as `58 / 4186 * 100 = 1.39%` after rounding. The repository is maintained by Mayin and describes a team solution; it does not assign sole authorship of all historical source files.
