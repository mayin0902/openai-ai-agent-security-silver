"""Prepare and serve the original solution inside the official Kaggle runtime."""
from __future__ import annotations

import glob
import importlib.util
import json
import os
import socket
import sys
from pathlib import Path

from build_submission import ROOT, build


def main() -> None:
    if socket.gethostname().split(".")[0].lower() == "gu04":
        raise SystemExit("Evaluation is not permitted on this login node.")
    working = Path("/kaggle/working")
    if not working.is_dir() or not Path("/kaggle/input").is_dir():
        raise SystemExit("Run this launcher in the official Kaggle competition runtime. For local checks, use unittest.")

    settings = json.loads((ROOT / "configs/competition.json").read_text(encoding="utf-8"))
    env_settings = {
        "AAS_GPT_NONMARKER_CANDIDATES": "GPT_CANDIDATES",
        "AAS_GEMMA_NONMARKER_CANDIDATES": "GEMMA_CANDIDATES",
        "AAS_SEARCH_PROBE_PER_PROFILE": "PROBE_CANDIDATES_PER_PROFILE",
        "AAS_SEARCH_TAIL_COUNT": "PROBE_TAIL_COUNT",
        "AAS_MAX_TOOL_HOPS": "MAX_TOOL_HOPS",
    }
    for variable, key in env_settings.items():
        os.environ[variable] = str(settings[key])
    for pattern in ("/kaggle/input/**/aicomp_sdk", "/kaggle/input/**/kaggle_evaluation"):
        for found in glob.glob(pattern, recursive=True):
            sys.path.insert(0, str(Path(found).parent))

    attack_path = build(working / "attack.py")
    spec = importlib.util.spec_from_file_location("aas_attack_submission", attack_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load the built attack entry point")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if len(module.GPT_SEARCH_PROFILES) != settings["GPT_K1_PROFILE_COUNT"]:
        raise ValueError("GPT profile count differs from competition settings")
    if len(module.GEMMA_SEARCH_PROFILES) != settings["GEMMA_K1_PROFILE_COUNT"]:
        raise ValueError("Gemma profile count differs from competition settings")

    for route, profiles in (("gpt_oss", module.GPT_SEARCH_PROFILES), ("gemma", module.GEMMA_SEARCH_PROFILES)):
        for profile in profiles:
            candidates = module._build_profile(profile, 3, route_hint=route)
            if len(candidates) != 3:
                raise ValueError(f"Unexpected candidate count: {profile}")
            module._assert_submission_shape(candidates)
        candidates = module.AttackAlgorithm({"route": route, "target_candidates": 3}).run(None, {})
        if len(candidates) != 3:
            raise ValueError(f"Unexpected route output: {route}")
        module._assert_submission_shape(candidates)
    print("Official-SDK candidate structure checks passed; starting evaluation server.")

    placeholder = "Id,Score\ngpt_oss_public,0.0\ngpt_oss_private,0.0\ngemma_public,0.0\ngemma_private,0.0\n"
    (working / "submission.csv").write_text(placeholder, encoding="utf-8")
    from kaggle_evaluation.jed_attack_134815.jed_attack_inference_server import JEDAttackInferenceServer
    JEDAttackInferenceServer().serve()


if __name__ == "__main__":
    main()
