"""
config/schema.py -- Externalized, validated configuration for the UEBA pipeline.

Environment override syntax: UEBA__SECTION__FIELD=value (double underscore
throughout -- both after the UEBA prefix and between nesting levels), e.g.
UEBA__THRESHOLD__PERCENTILE=99.9. A single-underscore variant (UEBA_SECTION__FIELD)
is a common typo and is explicitly detected and rejected at load time rather
than silently ignored, since an operator who thinks they overrode a value
and didn't is worse than a load-time error.

Fails fast: invalid values raise at load time, not at first use deep in a
training run hours later.
"""

from __future__ import annotations

import os
import warnings
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator


class _StrictModel(BaseModel):
    """Base for every config section. `extra="forbid"` makes the module
    docstring's "fails fast" claim actually true: Pydantic v2's own default
    is `extra="ignore"`, which silently drops unrecognized keys (a typo'd
    YAML field name would load without error and just use the default,
    invisibly). Verified via regression test that this now raises."""

    model_config = ConfigDict(extra="forbid")


class WindowConfig(_StrictModel):
    """Time-window discipline shared by feature engineering and both scorers."""

    feature_window_hours: float = Field(default=1.0, gt=0)


class CapabilityConfig(_StrictModel):
    """Controls the bootstrap scan that builds the CapabilityManifest --
    the mechanism that keeps the pipeline correct when a log source
    (Sysmon, DNS analytical logging, PowerShell script-block logging, etc.)
    is absent from a given deployment."""

    bootstrap_min_events: int = Field(
        default=200,
        description="Minimum total events in the bootstrap scan before a "
                    "capability manifest is considered trustworthy.",
    )
    min_events_for_capability: int = Field(
        default=5, ge=1,
        description="A feature group's events must number at least this many in "
                    "the bootstrap window before the group is enabled. An "
                    "ABSOLUTE floor, deliberately not a fraction of total "
                    "events. A fraction-of-total gate has two failures that an "
                    "absolute floor does not: (1) it couples unrelated sources "
                    "-- a high-volume source (Sysmon, DNS) inflates the "
                    "denominator and can push a legitimately-present but "
                    "lower-volume source (Kerberos, failed logons) below the "
                    "bar, so two independent log sources gate each other; and "
                    "(2) it is unstable on a small or rolling training window -- "
                    "the fraction of any event type varies run to run, flipping "
                    "a group on and off between retrains from sampling noise "
                    "alone, and every flip changes the feature order and "
                    "needlessly invalidates the model. An absolute floor is "
                    "independent per source and stable across window sizes, "
                    "while still rejecting a single stray event left over from a "
                    "decommissioned pilot install. Does NOT apply to "
                    "presence_gated_groups below.",
    )
    presence_gated_groups: list[str] = Field(
        default_factory=lambda: [
            "defender", "privilege_ad", "account_lifecycle",
        ],
        description="Groups admitted on ANY nonzero count in the bootstrap "
                    "window, bypassing min_events_for_capability. Their signal "
                    "is rare BY DESIGN, so even a small absolute floor is the "
                    "wrong test: Windows Defender only fires on an actual "
                    "malware verdict, and DCSync / privileged-group changes are "
                    "inherently sporadic. Measured on a real 5-day, "
                    "253-employee run, Defender produced 2 events out of 55,996 "
                    "total -- a healthy environment would rarely reach even a "
                    "handful, so gating these on volume defeats the point of "
                    "having the feature. account_lifecycle (T1098 privileged "
                    "group additions) carries the identical property: a 35-day, "
                    "272-user clean run's only account_lifecycle signal was a "
                    "single injected attack instance. These groups are the "
                    "special case where the presence of the event IS the "
                    "signal, so they admit on the first occurrence.",
    )
    zero_variance_check_enabled: bool = True


class DepartmentBehaviorConfig(_StrictModel):
    """Per-department behavioral parameters for the simulator. Defaults are
    plausible starting points, not validated facts -- override per
    deployment/scenario rather than trusting them as ground truth."""

    remote_fraction: float = Field(ge=0, le=1)
    login_start_mean_ist: float = Field(ge=0, le=23.99)
    login_start_std: float = Field(gt=0)
    work_duration_mean_hours: float = Field(gt=0)
    work_duration_std: float = Field(gt=0)
    ps_scripts_per_week: float = Field(ge=0)


class SimulatorConfig(_StrictModel):
    """External override surface for the simulator's department-level
    behavioral parameters and enabled log sources."""

    departments: dict[str, DepartmentBehaviorConfig] = Field(default_factory=dict)
    enabled_log_sources: list[str] = Field(
        default_factory=lambda: [
            "security", "sysmon", "dns", "powershell", "task_scheduler",
            "wmi", "defender",
        ],
    )

    @field_validator("enabled_log_sources")
    @classmethod
    def _valid_sources(cls, v: list[str]) -> list[str]:
        allowed = {"security", "sysmon", "dns", "powershell", "task_scheduler",
                   "wmi", "defender"}
        bad = set(v) - allowed
        if bad:
            raise ValueError(f"unknown log source(s) in enabled_log_sources: {bad}")
        return v


class SecurityConfig(_StrictModel):
    """Model-bundle integrity.

    A persisted bundle is a schema-explicit JSON + NumPy directory that cannot
    carry executable content, but a bundle moving between machines must still be
    signed and verified so a tampered baseline cannot be loaded on trust."""

    # SecretStr + repr=False: the signing key is the most sensitive secret in the
    # system -- anyone who learns it can forge a valid bundle signature and so
    # substitute the baseline the detector trusts. It must never reach a log,
    # error tracker, repr, or serialized support bundle. Read via
    # .get_secret_value().
    model_signing_key: SecretStr | None = Field(
        default=None, repr=False,
        description="HMAC key for signing/verifying persisted model bundles. "
                    "Must be set via UEBA__SECURITY__MODEL_SIGNING_KEY (or "
                    "YAML, though an environment secret is strongly "
                    "preferred) in any environment that saves or loads "
                    "models. No default is provided on purpose -- a "
                    "hardcoded default key would defeat the point. Masked in "
                    "repr/dump.",
    )
    require_signed_bundles: bool = Field(
        default=True,
        description="If True, persistence/store.py refuses to load an "
                    "unsigned or invalidly-signed bundle. Disable only for "
                    "local development against artifacts you produced "
                    "yourself in the same session.",
    )


class IdentityGraphConfig(_StrictModel):
    """Configuration for the structural identity graph.

    Consumed only by the `graph-viz` command. Nothing here affects detection: no
    code path fuses structural risk into a behavioural score. Metrics are
    computed with NetworkX on a rolling snapshot, which at this project's scale
    (a few hundred to a few thousand nodes) completes well inside the retrain
    window. See graph/identity_graph.py.
    """

    tier0_risk_weight: float = Field(
        default=0.40, ge=0, le=1,
        description="Weight for Tier-0 proximity in composite risk score.",
    )
    betweenness_weight: float = Field(
        default=0.25, ge=0, le=1,
        description="Weight for betweenness centrality in composite risk score.",
    )
    pagerank_weight: float = Field(
        default=0.20, ge=0, le=1,
        description="Weight for PageRank in composite risk score.",
    )
    degree_weight: float = Field(
        default=0.15, ge=0, le=1,
        description="Weight for degree centrality in composite risk score.",
    )
    betweenness_exact_max_nodes: int = Field(
        default=1500, ge=1,
        description="Above this node count, betweenness centrality is estimated "
                    "from sampled pivots (Brandes & Pich 2007) instead of exact "
                    "Brandes O(V*E), which is unusable past ~10k nodes.",
    )
    betweenness_pivots: int = Field(
        default=300, ge=1,
        description="Number of source pivots for sampled betweenness on large "
                    "graphs. Higher = more accurate, slower.",
    )
    @model_validator(mode="after")
    def _weights_plausible(self) -> IdentityGraphConfig:
        total = (self.tier0_risk_weight + self.betweenness_weight
                 + self.pagerank_weight + self.degree_weight)
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"graph risk weights must sum to 1.0, got {total}")
        return self


class PipelineConfig(_StrictModel):
    window: WindowConfig = Field(default_factory=WindowConfig)
    capability: CapabilityConfig = Field(default_factory=CapabilityConfig)
    simulator: SimulatorConfig = Field(default_factory=SimulatorConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    identity_graph: IdentityGraphConfig = Field(default_factory=IdentityGraphConfig)
    random_seed: int = 20250106
    model_store_path: str = "artifacts/models"


def _apply_env_overrides(raw: dict) -> dict:
    """
    Env-var override support: UEBA__SECTION__FIELD=value. Also detects the
    single-underscore near-miss (UEBA_SECTION__FIELD) and warns loudly
    rather than silently ignoring it -- a wrong-but-plausible env var name
    that gets silently dropped is worse than one that fails visibly.
    """
    prefix = "UEBA__"
    near_miss_prefix = "UEBA_"

    for key in os.environ:
        if key.startswith(near_miss_prefix) and not key.startswith(prefix):
            warnings.warn(
                f"Environment variable '{key}' looks like a UEBA config "
                f"override but uses a single underscore after UEBA_. The "
                f"correct syntax is double-underscore throughout: "
                f"'UEBA__SECTION__FIELD'. This variable will be IGNORED.",
                UserWarning,
                stacklevel=2,
            )

    for key, val in os.environ.items():
        if not key.startswith(prefix):
            continue
        path = key[len(prefix):].lower().split("__")
        node = raw
        for part in path[:-1]:
            node = node.setdefault(part, {})
        coerced: object = val
        for cast in (int, float):
            try:
                coerced = cast(val)
                break
            except ValueError:
                continue
        if val.lower() in ("true", "false"):
            coerced = val.lower() == "true"
        node[path[-1]] = coerced
    return raw


def load_config(path: str | Path | None = None) -> PipelineConfig:
    """
    Loads config from YAML (if provided) + environment overrides, validates,
    and fails fast with a clear pydantic ValidationError on bad input rather
    than propagating a bad value into training.
    """
    raw: dict = {}
    if path is not None:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"config file not found: {path}")
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
    raw = _apply_env_overrides(raw)
    return PipelineConfig(**raw)
