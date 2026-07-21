"""Non-executable, schema-explicit persistence for the trained engine.

WHY NOT PICKLE
--------------
The engine previously persisted with ``pickle`` behind an HMAC signature. The
signature guarantees integrity, but it does not change what ``pickle.loads``
*is*: a bytecode interpreter that reconstructs arbitrary Python objects and can
run arbitrary code during deserialization. In a security product the model file
is exactly the artifact an attacker would target — replace it, or leak the
signing key once, and loading it executes their code inside the detector. The
研究 basis is explicit that integrity protection does not remove this class of
risk (PickleBall, ACM CCS 2025); the accepted remedy is a serialization format
that has no code path to executing anything.

WHAT THIS FORMAT IS
-------------------
A bundle is a directory of two kinds of file, neither of which can carry code:

  * ``engine.json`` — every scalar, string, list and nested dict of the engine
    and its detectors, under an explicit, versioned schema. Loading walks the
    known schema and refuses anything it does not recognise; it never constructs
    a class named by the file.
  * ``*.npy`` — the numeric arrays (the empirical-null quantile grids), saved with
    ``numpy.save(..., allow_pickle=False)`` so a crafted array cannot smuggle a
    Python object either.

Integrity is still protected: ``manifest.sig`` is an HMAC-SHA256 over the sorted
digests of every file in the bundle, verified before any file is parsed. The
difference from before is defence in depth — even a bundle that somehow passes
the signature check (a leaked key) can, at worst, load bad *numbers*, never run
code.

The schema is closed and hand-written on purpose. Adding a field to a persisted
detector is a deliberate edit here, which is the point: nothing serializes by
default, so no field silently becomes attacker-controlled loader input.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Dict, Tuple

import numpy as np

SERIALIZATION_VERSION = "2.0.0"
_SIGNING_KEY_ENV = "UEBA__SECURITY__MODEL_SIGNING_KEY"

_STATE_NAME = "engine.json"
_SIG_NAME = "manifest.sig"


# ── signing key ─────────────────────────────────────────────────────────────
def signing_key() -> bytes:
    key = os.environ.get(_SIGNING_KEY_ENV)
    if not key:
        raise RuntimeError(
            f"{_SIGNING_KEY_ENV} is not set; refusing to sign/verify with an empty key"
        )
    return key.encode()


def _digest(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _bundle_signature(files: Dict[str, bytes]) -> bytes:
    """HMAC over the sorted per-file digests, so any file change breaks the seal."""
    payload = "\n".join(f"{name}:{_digest(blob)}" for name, blob in sorted(files.items()))
    return hmac.new(signing_key(), payload.encode(), hashlib.sha256).digest()


# ── empirical-null (p-value) grids ──────────────────────────────────────────
def pvalue_to_state(pv) -> dict:
    """The picklable content of an EmpiricalPValue, arrays separated out."""
    grid = None if pv._grid is None else np.asarray(pv._grid, dtype=np.float64)
    return {"grid_size": int(pv.grid_size), "n": int(pv._n), "_array": grid}


def pvalue_from_state(state: dict):
    from ueba_pipeline.models.pvalue import EmpiricalPValue

    pv = EmpiricalPValue(grid_size=int(state["grid_size"]))
    pv._n = int(state["n"])
    grid = state.get("_array")
    pv._grid = None if grid is None else np.asarray(grid, dtype=np.float64)
    return pv


# ── auth-graph detector ─────────────────────────────────────────────────────
def _edge_key(edge: Tuple[str, str]) -> str:
    # Edges are (src, dst) string tuples. JSON has no tuple key, so they are
    # joined on a delimiter that cannot occur in a normalised identity (all
    # inputs pass through _norm, which lowercases and strips but never inserts
    # this control character).
    return f"{edge[0]}\x1f{edge[1]}"


def _edge_from_key(key: str) -> Tuple[str, str]:
    src, dst = key.split("\x1f", 1)
    return (src, dst)


def graph_to_state(graph) -> dict:
    cfg = graph.config
    edges = {
        view: {
            _edge_key(edge): [st.total, st.tick_count, st.active_ticks, st.last_tick]
            for edge, st in view_edges.items()
        }
        for view, view_edges in graph._edges.items()
    }
    return {
        "config": {
            "tick_seconds": cfg.tick_seconds,
            "min_baseline_ticks": cfg.min_baseline_ticks,
            "alpha": cfg.alpha,
            "absorb_surprise": cfg.absorb_surprise,
        },
        "edges": edges,
        "seen": {view: [_edge_key(e) for e in edges] for view, edges in graph._seen.items()},
        "principals": {view: sorted(v) for view, v in graph._principals.items()},
        "img_hosts": {img: sorted(hosts) for img, hosts in graph._img_hosts.items()},
        "dst_counts": graph._dst_counts,
        "src_counts": graph._src_counts,
        "src_totals": graph._src_totals,
        "dst_totals": graph._dst_totals,
        "view_totals": dict(graph._view_totals),
        "global_tick": graph._global_tick,
        "ticks_seen": graph._ticks_seen,
    }


def graph_from_state(state: dict):
    from collections import defaultdict

    from ueba_pipeline.graph.auth_graph_anomaly import (
        AuthGraphAnomalyDetector, AuthGraphConfig, _EdgeState,
    )

    cfg = AuthGraphConfig(**state["config"])
    graph = AuthGraphAnomalyDetector(config=cfg)

    for view, view_edges in state["edges"].items():
        target = graph._edges[view]
        for key, (total, tick_count, active_ticks, last_tick) in view_edges.items():
            target[_edge_from_key(key)] = _EdgeState(
                total=float(total), tick_count=float(tick_count),
                active_ticks=int(active_ticks), last_tick=int(last_tick),
            )
    for view, keys in state["seen"].items():
        graph._seen[view] = {_edge_from_key(k) for k in keys}
    for view, principals in state["principals"].items():
        graph._principals[view] = set(principals)
    for img, hosts in state["img_hosts"].items():
        graph._img_hosts[img] = set(hosts)
    graph._dst_counts = {v: dict(m) for v, m in state["dst_counts"].items()}
    graph._src_counts = {v: dict(m) for v, m in state["src_counts"].items()}
    graph._src_totals = {v: dict(m) for v, m in state["src_totals"].items()}
    graph._dst_totals = {v: dict(m) for v, m in state["dst_totals"].items()}
    graph._view_totals = defaultdict(float, state["view_totals"])
    graph._global_tick = int(state["global_tick"])
    graph._ticks_seen = int(state["ticks_seen"])
    return graph


# ── volumetric detector ─────────────────────────────────────────────────────
def volumetric_to_state(vol) -> Tuple[dict, Dict[str, np.ndarray]]:
    """Return (json-safe state, {array_name: ndarray}) for the volumetric track.

    The per-entity mean/std vectors and the ECOD internals are arrays; they are
    handed back separately so they can be written as .npy rather than embedded as
    JSON number lists (smaller, exact, and pickle-free).
    """
    arrays: Dict[str, np.ndarray] = {}
    if vol._global_mean is not None:
        arrays["vol_global_mean"] = np.asarray(vol._global_mean, dtype=np.float64)
        arrays["vol_global_std"] = np.asarray(vol._global_std, dtype=np.float64)

    entities = sorted(vol._entity_mean)
    if entities:
        arrays["vol_entity_means"] = np.stack([vol._entity_mean[e] for e in entities])
        arrays["vol_entity_stds"] = np.stack([vol._entity_std[e] for e in entities])

    model_state = None
    if vol._model is not None:
        model_state = ecod_to_state(vol._model, arrays)

    return {
        "feature_order": list(vol.feature_order),
        "entities": entities,
        "has_global": vol._global_mean is not None,
        "model": model_state,
    }, arrays


def volumetric_from_state(state: dict, arrays: Dict[str, np.ndarray]):
    from ueba_pipeline.models.volumetric_detector import VolumetricDetector

    vol = VolumetricDetector(feature_order=list(state["feature_order"]))
    if state["has_global"]:
        vol._global_mean = arrays["vol_global_mean"]
        vol._global_std = arrays["vol_global_std"]
    entities = state["entities"]
    if entities:
        means, stds = arrays["vol_entity_means"], arrays["vol_entity_stds"]
        vol._entity_mean = {e: means[i] for i, e in enumerate(entities)}
        vol._entity_std = {e: stds[i] for i, e in enumerate(entities)}
    if state["model"] is not None:
        vol._model = ecod_from_state(state["model"], arrays)
    return vol


def ecod_to_state(model, arrays: Dict[str, np.ndarray]) -> dict:
    """Serialise the fitted InductiveECOD against its explicit schema.

    ``_grids`` is a per-column list of quantile grids; the columns can differ in
    length, so they are stacked only when uniform and otherwise stored as
    separate arrays keyed by column index. Nothing is discovered by reflection —
    a new fitted attribute is a deliberate addition here.
    """
    grids = [np.asarray(g, dtype=np.float64) for g in model._grids]
    uniform = bool(grids) and len({g.shape for g in grids}) == 1
    if uniform:
        arrays["ecod_grids"] = np.stack(grids)
    else:
        for j, grid in enumerate(grids):
            arrays[f"ecod_grid_{j}"] = grid
    if model._skew_sign is not None:
        arrays["ecod_skew_sign"] = np.asarray(model._skew_sign, dtype=np.float64)
    if model.decision_scores_ is not None:
        arrays["ecod_decision_scores"] = np.asarray(model.decision_scores_, dtype=np.float64)

    return {
        "grid_size": model.grid_size,
        "n_grids": len(grids),
        "grids_uniform": uniform,
        "n_train": int(model._n_train),
        "floor": float(model._floor),
        "has_skew_sign": model._skew_sign is not None,
        "has_decision_scores": model.decision_scores_ is not None,
    }


def ecod_from_state(state: dict, arrays: Dict[str, np.ndarray]):
    from ueba_pipeline.models.inductive_ecod import InductiveECOD

    model = InductiveECOD(grid_size=state["grid_size"])
    if state["grids_uniform"]:
        model._grids = list(arrays["ecod_grids"])
    else:
        model._grids = [arrays[f"ecod_grid_{j}"] for j in range(state["n_grids"])]
    model._n_train = int(state["n_train"])
    model._floor = float(state["floor"])
    if state["has_skew_sign"]:
        model._skew_sign = arrays["ecod_skew_sign"]
    if state["has_decision_scores"]:
        model.decision_scores_ = arrays["ecod_decision_scores"]
    return model


# ── capability manifest ─────────────────────────────────────────────────────
def manifest_to_state(manifest) -> dict:
    if manifest is None:
        return {"present": False}
    return {"present": True, "manifest": manifest.to_dict()}


def manifest_from_state(state: dict):
    if not state.get("present"):
        return None
    from ueba_pipeline.features.manifest import CapabilityManifest

    return CapabilityManifest.from_dict(state["manifest"])


# ── whole-engine bundle ─────────────────────────────────────────────────────
def engine_to_bundle(engine) -> Tuple[dict, Dict[str, np.ndarray]]:
    arrays: Dict[str, np.ndarray] = {}

    graph_nulls = {}
    for view, pv in engine._graph_nulls.items():
        st = pvalue_to_state(pv)
        if st.pop("_array") is not None:
            arrays[f"gnull_{view}"] = np.asarray(pv._grid, dtype=np.float64)
        graph_nulls[view] = {**st, "has_array": f"gnull_{view}" in arrays}

    vol_null = None
    if engine._vol_null is not None:
        st = pvalue_to_state(engine._vol_null)
        if st.pop("_array") is not None:
            arrays["vol_null"] = np.asarray(engine._vol_null._grid, dtype=np.float64)
        vol_null = {**st, "has_array": "vol_null" in arrays}

    vol_state, vol_arrays = volumetric_to_state(engine.volumetric)
    arrays.update(vol_arrays)

    cfg = engine.config
    state = {
        "serialization_version": SERIALIZATION_VERSION,
        "config": {
            "window_hours": cfg.window_hours,
            "alert_mode": cfg.alert_mode,
            "alert_fdr": cfg.alert_fdr,
            "alert_budget_per_day": cfg.alert_budget_per_day,
            "stream_watermark_hours": cfg.stream_watermark_hours,
            "enable_volumetric": cfg.enable_volumetric,
            "null_calibration_fraction": cfg.null_calibration_fraction,
        },
        "graph": graph_to_state(engine.graph),
        "graph_nulls": graph_nulls,
        "vol_null": vol_null,
        "volumetric": vol_state,
        "manifest": manifest_to_state(engine.manifest),
        "view_stats": engine.view_stats,
    }
    return state, arrays


def engine_from_bundle(state: dict, arrays: Dict[str, np.ndarray]):
    from ueba_pipeline.engine import EngineConfig, TwoTrackEngine

    version = state.get("serialization_version")
    if version != SERIALIZATION_VERSION:
        raise ValueError(
            f"bundle serialization version {version!r} is not supported by this "
            f"build ({SERIALIZATION_VERSION!r})"
        )

    engine = TwoTrackEngine(config=EngineConfig(**state["config"]))
    engine.graph = graph_from_state(state["graph"])
    engine.manifest = manifest_from_state(state["manifest"])
    engine.view_stats = state["view_stats"]

    graph_nulls = {}
    for view, st in state["graph_nulls"].items():
        arr = arrays.get(f"gnull_{view}") if st.get("has_array") else None
        graph_nulls[view] = pvalue_from_state({**st, "_array": arr})
    engine._graph_nulls = graph_nulls

    if state["vol_null"] is not None:
        st = state["vol_null"]
        arr = arrays.get("vol_null") if st.get("has_array") else None
        engine._vol_null = pvalue_from_state({**st, "_array": arr})

    engine.volumetric = volumetric_from_state(state["volumetric"], arrays)
    return engine


# ── disk I/O ────────────────────────────────────────────────────────────────
class _NumpyJSONEncoder(json.JSONEncoder):
    """Coerce numpy scalars that slip into the schema to native types.

    Array *data* never travels through JSON — it goes to .npy — but a stray
    numpy float in a counter dict (e.g. a view total) would otherwise break the
    dump. Coercing it keeps the JSON path pure-Python and readable.
    """

    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        return super().default(obj)


def save_engine(engine, directory: str) -> None:
    """Write ``engine`` as a signed, non-executable bundle under ``directory``."""
    import io

    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)

    state, arrays = engine_to_bundle(engine)

    files: Dict[str, bytes] = {}
    files[_STATE_NAME] = json.dumps(
        state, sort_keys=True, cls=_NumpyJSONEncoder).encode("utf-8")
    for name, array in sorted(arrays.items()):
        buffer = io.BytesIO()
        np.save(buffer, np.ascontiguousarray(array), allow_pickle=False)
        files[f"{name}.npy"] = buffer.getvalue()

    signature = _bundle_signature(files)

    # Remove any stale files from a previous, differently-shaped bundle so the
    # signature always describes exactly what is on disk.
    for existing in path.glob("*"):
        if existing.name in (_STATE_NAME, _SIG_NAME) or existing.suffix == ".npy":
            existing.unlink()
    for name, blob in files.items():
        (path / name).write_bytes(blob)
    (path / _SIG_NAME).write_bytes(signature)


def load_engine(directory: str):
    """Load a bundle after verifying its signature. Never executes bundle content."""
    import io

    path = Path(directory)
    files: Dict[str, bytes] = {}
    for file in sorted(path.glob("*")):
        if file.name == _SIG_NAME:
            continue
        if file.name == _STATE_NAME or file.suffix == ".npy":
            files[file.name] = file.read_bytes()

    signature = (path / _SIG_NAME).read_bytes()
    if not hmac.compare_digest(_bundle_signature(files), signature):
        raise ValueError("engine bundle signature verification failed")

    state = json.loads(files[_STATE_NAME].decode("utf-8"))
    arrays: Dict[str, np.ndarray] = {}
    for name, blob in files.items():
        if name.endswith(".npy"):
            # allow_pickle=False is the load-side guarantee: a .npy that encodes a
            # Python object (the numpy RCE vector) is rejected rather than executed.
            arrays[name[:-4]] = np.load(io.BytesIO(blob), allow_pickle=False)

    return engine_from_bundle(state, arrays)
