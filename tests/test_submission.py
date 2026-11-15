"""Offline structural checks. The SDK double is not a model or evaluator."""
from __future__ import annotations

import ast
import hashlib
import json
import os
import sys
import types
import unittest
from contextlib import ExitStack
from dataclasses import dataclass
from unittest.mock import patch

from scripts.build_submission import ROOT, assignment, build_source


@dataclass(frozen=True)
class CandidateDouble:
    user_messages: tuple[str, ...]


class AlgorithmDouble:
    def __init__(self, config=None):
        self.config = dict(config or {})


def sdk_double():
    modules = {name: types.ModuleType(name) for name in (
        "aicomp_sdk", "aicomp_sdk.attacks", "aicomp_sdk.evaluation", "aicomp_sdk.evaluation.ops")}
    modules["aicomp_sdk"].__path__ = []
    modules["aicomp_sdk.evaluation"].__path__ = []
    attacks = modules["aicomp_sdk.attacks"]
    attacks.AttackAlgorithmBase = AlgorithmDouble
    attacks.AttackCandidate = CandidateDouble
    attacks.AttackRunConfig = dict
    modules["aicomp_sdk.evaluation.ops"].MAX_REPLAY_FINDINGS = 2000
    return modules


class ProvenanceTests(unittest.TestCase):
    def test_original_and_module_checksums(self):
        manifest = json.loads((ROOT / "reference/provenance.json").read_text(encoding="utf-8"))
        original = (ROOT / manifest["source_artifact"]).read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(), manifest["sha256"])
        for name, expected in manifest["modules"].items():
            with self.subTest(module=name):
                source = (ROOT / (name.replace(".", "/") + ".py")).read_text(encoding="utf-8")
                self.assertEqual(hashlib.sha256(source.encode()).hexdigest(), expected)

    def test_build_matches_original_attack_exactly(self):
        original = (ROOT / "reference/original_submission.py").read_text(encoding="utf-8-sig")
        attack = ast.literal_eval(assignment(ast.parse(original), "attack_code").value)
        self.assertEqual(build_source(), attack)

    def test_competition_settings_match_original_notebook(self):
        tree = ast.parse((ROOT / "reference/original_submission.py").read_text(encoding="utf-8-sig"))
        settings = json.loads((ROOT / "configs/competition.json").read_text(encoding="utf-8"))
        for name, value in settings.items():
            with self.subTest(setting=name):
                self.assertEqual(ast.literal_eval(assignment(tree, name).value), value)


class CandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stack = ExitStack()
        cls.addClassCleanup(cls.stack.close)
        # Avoid developer environment settings affecting the artifact checks.
        cls.stack.enter_context(patch.dict(os.environ, {}, clear=True))
        cls.stack.enter_context(patch.dict(sys.modules, sdk_double()))
        cls.module = types.ModuleType("offline_submission_check")
        cls.module.__file__ = str(ROOT / "dist/attack.py")
        exec(compile(build_source(), cls.module.__file__, "exec"), cls.module.__dict__)

    def test_all_40_profiles_generate_valid_deterministic_candidates(self):
        for route, profiles in (("gpt_oss", self.module.GPT_SEARCH_PROFILES),
                                ("gemma", self.module.GEMMA_SEARCH_PROFILES)):
            self.assertEqual(len(profiles), 20)
            self.assertEqual(len(set(profiles)), 20)
            for profile in profiles:
                with self.subTest(route=route, profile=profile):
                    first = self.module._build_profile(profile, 3, route_hint=route)
                    second = self.module._build_profile(profile, 3, route_hint=route)
                    self.assertEqual(first, second)
                    self.assertEqual(len(first), 3)
                    self.module._assert_submission_shape(first)
                    self.assertEqual(len({tuple(c.user_messages) for c in first}), 3)

    def test_both_model_routes_without_environment(self):
        for route in ("gpt_oss", "gemma"):
            with self.subTest(route=route):
                candidates = self.module.AttackAlgorithm({"route": route, "target_candidates": 4}).run(None, {})
                self.assertEqual(len(candidates), 4)
                self.module._assert_submission_shape(candidates)

    def test_explicit_route_overrides_environment_and_fallback_order(self):
        with patch.dict(os.environ, {"AAS_FORCE_ROUTE": "gemma"}):
            self.assertEqual(self.module._select_route({"route": "gpt-oss"})[0], "gpt_oss")
            self.assertEqual(self.module._select_route({})[0], "gemma")
        with patch.object(self.module, "_RUN_INDEX", 0):
            self.assertEqual(self.module._select_route({})[0], "gpt_oss")
            self.assertEqual(self.module._select_route({})[0], "gemma")

    def test_shape_guard_rejects_marker_and_multiple_messages(self):
        with self.assertRaises(AssertionError):
            self.module._assert_submission_shape([CandidateDouble(("a", "b"))])
        with self.assertRaises(AssertionError):
            self.module._assert_submission_shape([CandidateDouble((self.module.FORBIDDEN_MARKER,))])

    def test_candidate_limits(self):
        self.assertEqual(self.module._clamp_count(0), 1)
        self.assertEqual(self.module._clamp_count(2500), 2000)

    def test_trace_feedback_ignores_failed_or_unscored_actions(self):
        trace = {"tool_events": [
            {"name": "email.send", "ok": True},
            {"name": "email.send", "ok": False},
            {"name": "web.search", "ok": True},
            {"function": {"name": "fs.write"}, "success": True},
            {"name": "shell.run", "error": "denied"},
        ]}
        self.assertEqual(self.module._count_scoring_actions(trace), 2)
        self.assertEqual(self.module._raw_estimate(0), 0)
        self.assertEqual(self.module._raw_estimate(2), 10)

    def test_selection_uses_reward_per_time_on_probe_tail(self):
        profiles = self.module.GPT_SEARCH_PROFILES[:2]
        # A: misleading first probe, then 6 reward / 10s. B: 6 reward / 1s.
        observations = [(0.001, 100), (10.0, 1), (10.0, 1),
                        (0.001, 0), (1.0, 1), (1.0, 1)]
        with patch.object(self.module, "PROBE_CANDIDATES_PER_PROFILE", 3), \
             patch.object(self.module, "PROBE_TAIL_COUNT", 2), \
             patch.object(self.module, "_probe_candidate", side_effect=observations):
            selected, rows = self.module._select_profile_by_probe(object(), profiles, "gpt_oss", 8)
        self.assertEqual(selected, profiles[1])
        self.assertEqual(rows[0]["tail_actions"], [1, 1])


if __name__ == "__main__":
    unittest.main()
