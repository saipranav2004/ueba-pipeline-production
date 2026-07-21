"""Evaluation — one implementation, driving the shipped BehavioralEngine.

`honest_eval` is the causal out-of-time harness (see BENCHMARK.md for the
guarantees it enforces). `benchmark` and `lanl_adapter` support validation on
public labelled datasets (LANL 2015, OpTC).
"""
from ueba_pipeline.evaluation.honest_eval import evaluate, render

__all__ = ["evaluate", "render"]
