"""Streaming authentication-graph anomaly detector.

Detection substrate for the lateral-movement / credential-abuse attack class,
where the signal is a *relationship* (who authenticated to what, from where)
rather than a per-entity feature histogram. Each authentication event is
projected onto directed edges of an identity graph and scored online.

Two complementary, unsupervised signals are combined per edge:

1. Edge novelty. A first-time-seen (principal -> resource) relationship for an
   entity, relative to the causal baseline. This is the "New Authentication"
   filter of Bowman et al., "Detecting Lateral Movement in Enterprise Computer
   Networks with Unsupervised Graph AI" (RAID 2020), which reported ~85% TPR at
   0.9% FPR on LANL -- far above non-graph ML on the same data.

2. Microcluster burst. A sudden group of similar edges (fan-out / spray / a
   forged credential reused rapidly). This is the MIDAS score of Bhatia et al.,
   "MIDAS: Microcluster-Based Detector of Anomalies in Edge Streams" (AAAI
   2020): a chi-squared surprise between an edge's current-tick count and its
   running mean. We implement MIDAS with exact per-edge
   counters. Constant-memory count-min sketches (the paper's mechanism) swap in
   behind the same interface at production scale; exact counters are used here
   because the estate size makes them cheap and removes sketch collision noise
   during detection-quality validation.

Scoring is read-only with respect to attack absorption (MIDAS-F rationale,
Bhatia et al. TKDD 2022): a flagged edge is not folded into the baseline, so an
attacker cannot normalise their own behaviour by repetition.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

# Windows logon types that represent a *remote* authentication (an edge between
# two hosts) rather than a local/console session. 3 = network, 10 = remote
# interactive (RDP). Interactive (2) and service (5) logons are same-host and
# are ignored for the host->host projection.
REMOTE_LOGON_TYPES = {"3", "10"}




# Event id -> privileged directory-operation class, for the dir_op view. This is
# the extension point for directory coverage: a new operation is a row here, not a
# new code path. Classes are deliberately coarse and low-cardinality -- the view
# asks "which principals perform this KIND of privileged operation", which is
# stable per principal, rather than "which object did they touch", which is not.
DIR_OP_CLASS = {
    "4728": "groupadd",     "4732": "groupadd",     "4756": "groupadd",
    "4729": "groupremove",  "4733": "groupremove",
    "4720": "acctcreate",   "4726": "acctdelete",
    "4722": "acctenable",   "4725": "acctdisable",
    "4724": "pwreset",      "4738": "acctchange",
    "4662": "adobjaccess",  "5136": "attrmodify",
}


def _basename(path) -> str:
    if not path:
        return ""
    p = str(path).replace("\\", "/").strip().lower()
    return p.rsplit("/", 1)[-1]


# Values Windows writes when a field is absent; a workstation name is only a
# usable identity if it is none of these.
_NO_IDENTITY = {"", "-", "null", "none", "unknown", "workstation"}


def _source_identity(fields) -> str:
    """The stable identity of where an authentication came from.

    Prefers the workstation/device name over the source IP. An IP is not a stable
    identity in a real estate: DHCP leases expire, VPN pools hand out whatever is
    free, and Wi-Fi and wired interfaces on the same laptop differ -- so keying the
    (account -> source) edge on an address turns routine address churn into a
    stream of novel edges, which is the single largest source of real-world false
    positives for authentication-graph detection. The device name survives all of
    it. This is also how the public authentication corpora are constructed (LANL
    records source and destination *computers*, not addresses).

    Falls back to the address when there is no device name -- external and
    spray-style traffic, where the address is the only identity available and is
    itself the thing worth learning.
    """
    ws = _norm(fields.get("workstation"))
    if ws and ws not in _NO_IDENTITY:
        return ws
    return _norm(fields.get("src_ip"))


@dataclass
class _EdgeState:
    total: float = 0.0            # count over all ticks
    tick_count: float = 0.0       # occurrences within last_tick
    active_ticks: int = 0         # number of distinct ticks the edge appeared in
    last_tick: int = -1


@dataclass
class AuthGraphConfig:
    """Configuration for the graded edge-surprise scorer.

    Edge anomaly is graded surprise in nats, not a novelty flag. There is no
    constant "score for a novel edge": a first-time-seen edge is scored by how
    improbable it is under the estate's learned access distribution, which is
    what lets one threshold separate routine churn from a genuine first contact.
    """

    tick_seconds: int = 3600       # graph time resolution (1 hour)
    min_baseline_ticks: int = 1    # warmup before burst scoring is trusted
    # Dirichlet concentration for the back-off to the global destination
    # marginal. alpha -> 0 trusts the per-source history completely (every novel
    # edge becomes infinitely surprising); alpha -> inf ignores it. 1.0 is the
    # neutral, uninformative default, deliberately not tuned against the
    # benchmark.
    alpha: float = 1.0
    # Surprise above which an edge is NOT folded into the baseline (MIDAS-F), so
    # an attacker cannot launder repeated abuse into normality. In nats, and
    # reachable by construction: surprise is unbounded above.
    absorb_surprise: float = 12.0
    # Relationship views the detector projects onto. ``None`` means every view
    # ``edges_for`` can emit. Restricting the set is how a view's contribution is
    # measured: scripts/ablate_graph_views.py drops each in turn and re-runs the
    # benchmark, so a view is kept on measured recall rather than on the
    # plausibility of its rationale.
    enabled_views: Optional[frozenset] = None


@dataclass
class AuthGraphAnomalyDetector:
    """Online edge-anomaly scorer over the authentication graph.

    Maintains, per edge *projection*, decayed counters and a seen-set. Call
    :meth:`score_event` for each normalized auth event in time order. The score
    is the max anomaly over the event's projections; ``absorb`` folds the event
    into the baseline unless it looks anomalous.
    """

    config: AuthGraphConfig = field(default_factory=AuthGraphConfig)
    _edges: Dict[str, Dict[Tuple[str, str], _EdgeState]] = field(default_factory=lambda: defaultdict(dict))
    _seen: Dict[str, set] = field(default_factory=lambda: defaultdict(set))
    _global_tick: int = 0
    _ticks_seen: int = 0
    # Principals (edge source) seen per view during baseline. Used to gate
    # novelty for views where entities have a dense baseline: a *change* for a
    # known entity is meaningful, its first-ever appearance is not.
    _principals: Dict[str, set] = field(default_factory=lambda: defaultdict(set))
    # Sufficient statistics for the Dirichlet-smoothed conditional
    # P(dst | src) = (c_sd + alpha * pi_d) / (n_s + alpha).
    # All three are plain counters: O(1) update, streaming-safe, no retraining.
    # Plain dicts rather than a nested defaultdict, so the state serialises to an
    # explicit schema without a factory the loader would have to reconstruct.
    _dst_counts: Dict[str, Dict[str, float]] = field(default_factory=dict)
    _src_counts: Dict[str, Dict[str, float]] = field(default_factory=dict)
    _src_totals: Dict[str, Dict[str, float]] = field(default_factory=dict)
    _dst_totals: Dict[str, Dict[str, float]] = field(default_factory=dict)
    _view_totals: Dict[str, float] = field(default_factory=lambda: defaultdict(float))

    # -- edge extraction ----------------------------------------------------
    def edges_for(self, event) -> list[Tuple[str, Tuple[str, str]]]:
        """Project one normalized event onto ``(view, (src, dst))`` edges.

        Edges are drawn from remote logons (4624/4625, logon type 3/10),
        credential-store process access (Sysmon 10 to lsass/ntds), and Kerberos
        ticket requests (4768/4769). A plain (user -> source-IP) novelty on TGT
        requests is *not* emitted: users legitimately request tickets from many
        sources, so that projection is benign churn; only the encryption/pre-auth
        *context* of a ticket is used (kerb_ctx view).

        Views scored independently:
          - ``user_src``: an account authenticating from a host/IP it has never
            used -- forged-ticket / PtH from an attacker foothold.
          - ``proc_access``: a process accessing another process it never has
            on this host -- credential-store dumping (e.g. lsass) shows up as a
            novel process-access edge; the access mask / target is not
            hardcoded, novelty + natural rarity decide what matters.
          - ``kerb_ctx``: an account requesting a ticket with an encryption /
            pre-auth context it has never used -- AS-REP roasting and RC4
            kerberoasting present as a downgrade novel to that account.
        """
        f = event.fields
        et = event.event_type
        out: list[Tuple[str, Tuple[str, str]]] = []

        if et.startswith("4624") or et.startswith("4625"):
            logon_type = str(f.get("logon_type") or "")
            if logon_type not in REMOTE_LOGON_TYPES:
                return out
            user = _norm(f.get("target_user_name"))
            src = _source_identity(f)
            dst = _norm(event.computer_name)
            if user and src:
                out.append(("user_src", (user, src)))
        elif et.startswith("sysmon_10"):
            # Generic: novelty of ANY (source-process -> target-process) access
            # edge for this host. No attack-specific target list -- a process
            # accessing something it never has is the signal, and rarity/novelty
            # decides which matters (credential-store access is naturally rare).
            target = _basename(f.get("target_image"))
            src_img = _basename(f.get("source_image"))
            host = _norm(event.computer_name)
            if src_img and target:
                out.append(("proc_access", (host + "|" + src_img, target)))
        elif et.startswith("4768"):
            user = _norm(f.get("target_user_name"))
            enc = _norm(f.get("ticket_enc_type"))
            pre = _norm(f.get("pre_auth_type"))
            if user and enc:
                out.append(("kerb_ctx", (user, enc + "|" + pre)))
        elif et == "4769":
            # Service-ticket ENCRYPTION context: (account -> ticket enc type).
            # Deliberately keyed on the low-cardinality encryption type (a handful
            # of values: AES 0x12, RC4 0x17, ...), NOT the service name. Keying on
            # the SPN floods the null -- users legitimately reach many services,
            # so (user, SPN) novelty fires on benign churn and drowns the signal
            # (measured: it collapsed graph recall from 43/60 to 1/60). The
            # encryption context is the generalized ticket-DOWNGRADE signal: an
            # account that has only ever received modern (AES) service tickets
            # suddenly receiving RC4 is a novel, rare context -- exactly the
            # Kerberoasting / RC4-downgrade pattern -- while an account's routine
            # cipher is a seen edge that decays to ~0. Machine SPNs excluded.
            user = _norm(f.get("target_user_name"))
            enc = _norm(f.get("ticket_enc_type"))
            spn = _norm(f.get("service_name"))
            if user and enc and not spn.endswith("$"):
                out.append(("tgs_enc", (user, enc)))
        elif et in DIR_OP_CLASS:
            # Privileged directory operation: (actor -> operation class).
            #
            # Keyed on the OPERATION, not the object it touched. Keying on the
            # object -- (actor -> group:X) -- makes the destination space large and
            # sparsely visited: an admin's routine access-request work lands on a
            # different group almost every time, so ~72% of benign edges are novel
            # and novelty stops meaning anything (measured; see docs/evaluation.md's
            # per-view novelty table). The operation class is low-cardinality and
            # stable per principal: the handful of admins who manage the directory
            # do the same operations daily, so those edges are seen and score ~0.
            #
            # The signal is then carried by the REVERSE conditional: a directory
            # operation has only ever been performed by a few admin principals, so
            # a regular account performing one at all gives P(actor | operation)
            # a tiny value and a high surprise -- without any group allow/deny
            # list, Tier-0 label, or attack-specific branch. Adding coverage of a
            # new directory operation is a row in DIR_OP_CLASS, not new logic.
            actor = _norm(f.get("subject_user_name"))
            if actor and not actor.endswith("$"):
                out.append(("dir_op", (actor, DIR_OP_CLASS[et])))
        enabled = self.config.enabled_views
        if enabled is not None:
            out = [(view, edge) for view, edge in out if view in enabled]
        return out

    # -- scoring ------------------------------------------------------------
    def score_event_views(self, event, absorb: bool = True) -> "list[Tuple[str, float]]":
        """Return ``[(view, surprise), ...]`` for every edge this event projects.

        Each view is scored independently so its surprise can be calibrated
        against that view's own benign null (see engine.py): a relationship type
        with a structurally high or churny benign baseline is thereby contained
        to its own view rather than setting the bar for every other view. Absorbs
        each edge into the baseline unless it looks anomalous (``absorb=True``).
        """
        tick = self._tick_of(event)
        if tick is None:
            return []
        out: "list[Tuple[str, float]]" = []
        for view, edge in self.edges_for(event):
            s = self._score_edge(view, edge, tick)
            if absorb:
                self._absorb(view, edge, tick, s)
            out.append((view, s))
        return out

    def score_event(self, event, absorb: bool = True) -> float:
        """Return the max edge-anomaly surprise for ``event`` (0.0 if no edges).

        Used where a single scalar surprise is wanted (streaming yield, the
        raw-surprise benchmark). The engine's detection path uses
        :meth:`score_event_views` so it can calibrate each view separately.
        """
        return max((s for _, s in self.score_event_views(event, absorb=absorb)),
                   default=0.0)

    def _score_edge(self, view: str, edge: Tuple[str, str], tick: int) -> float:
        novel = edge not in self._seen[view]
        st = self._edges[view].get(edge)

        if self._ticks_seen < self.config.min_baseline_ticks or st is None:
            burst = 0.0
        else:
            # Occurrences of this edge in the current tick, including this event.
            a = (st.tick_count if st.last_tick == tick else 0.0) + 1.0
            # A single occurrence is never a microcluster -- only a sudden group
            # of the same edge in one tick (fan-out, spray, forged-ticket reuse)
            # is. This avoids flagging benign edges that simply recur after an
            # idle gap (e.g. a daily logon), whose per-tick mean is small.
            if a < 2.0:
                burst = 0.0
            else:
                # Mean over the ticks the edge was actually active, not over all
                # elapsed ticks -- otherwise idle hours (nights, weekends) drag
                # the baseline rate below 1 and a benign edge recurring 2-3x in a
                # busy hour looks like a microcluster. A true burst is many more
                # occurrences than the edge's normal active-hour rate.
                # Poisson surprise of the current-tick count vs the edge's
                # normal active-hour rate; large only for a genuine spike.
                mean = st.total / max(st.active_ticks, 1)
                chi = ((a - mean) ** 2) / max(mean, 1e-6)
                burst = math.log1p(max(chi, 0.0))

        return self._surprise(view, edge) + burst

    def _surprise(self, view: str, edge: Tuple[str, str]) -> float:
        """Bidirectional Dirichlet-smoothed edge surprise, in nats.

            surprise = max( -log P(dst | src), -log P(src | dst) )
            P(b | a)  = (c_ab + alpha * pi_b) / (n_a + alpha)

        with pi_b the global marginal for b in this view (Laplace smoothed).
        Standard Dirichlet-multinomial back-off; the cheap, streaming,
        per-estate-learned counterpart to the peer-based null of Turcotte,
        Moore, Heard & McPhall (IEEE ISI 2016), whose anomaly score is likewise
        an upper-tail probability under a learnt model of a principal's activity.

        BOTH DIRECTIONS ARE NEEDED. Conditioning only on the source answers "did
        this principal go somewhere new?" -- right for user->host auth edges, and
        blind to "was this destination reached by someone new?", which is the
        whole signal for proc_access: where only wininit.exe opens lsass.exe,
        pi(lsass) ~ 1 and rundll32.exe opening lsass scores 0.0 under the forward
        conditional. The reverse conditional scores it high. Taking the max keeps
        each view's informative direction without hand-assigning one per view.

        Semantics:
          * novel edge to a POPULAR destination -> LOW surprise. This is the
            routine-churn class (everyone eventually touches the DC, the file
            server, the VDI egress IP) that dominated the false positives; the
            old code scored it identically to a genuine first contact.
          * novel edge to a RARE destination -> HIGH surprise.
          * novel edge from a HIGHLY ACTIVE source -> HIGHER surprise: it had
            many opportunities and never took them, so the absence is evidence.
          * COLD START -> ~0 surprise. With no baseline, pi = 1 and surprise = 0:
            nothing is surprising without evidence, so a brand-new account's
            first edge does not alert.
          * a SEEN edge decays smoothly toward 0 instead of falling off a cliff,
            so the score is continuous and rankable.
        """
        src, dst = edge
        a = self.config.alpha
        st = self._edges[view].get(edge)
        c = st.total if st else 0.0
        total = self._view_totals[view]

        def _cond(counts_b, totals_a, key_a, key_b) -> float:
            n_a = totals_a.get(view, {}).get(key_a, 0.0)
            marg = counts_b.get(view, {})
            pi_b = (marg.get(key_b, 0.0) + 1.0) / (total + max(len(marg), 1))
            p = (c + a * pi_b) / (n_a + a)
            return -math.log(max(min(p, 1.0), 1e-12))

        fwd = _cond(self._dst_counts, self._src_totals, src, dst)   # P(dst | src)
        rev = _cond(self._src_counts, self._dst_totals, dst, src)   # P(src | dst)
        return max(fwd, rev)

    def _absorb(self, view: str, edge: Tuple[str, str], tick: int, score: float) -> None:
        # MIDAS-F: do not let a flagged edge normalise itself into the baseline.
        if score >= self.config.absorb_surprise:
            return
        self._seen[view].add(edge)
        self._principals[view].add(edge[0])
        st = self._edges[view].get(edge)
        if st is None:
            st = _EdgeState()
            self._edges[view][edge] = st
        if st.last_tick != tick:
            st.tick_count = 0.0
            st.last_tick = tick
            st.active_ticks += 1
        st.tick_count += 1.0
        st.total += 1.0
        for store, k in ((self._dst_counts, edge[1]), (self._src_counts, edge[0]),
                         (self._src_totals, edge[0]), (self._dst_totals, edge[1])):
            m = store.setdefault(view, {})
            m[k] = m.get(k, 0.0) + 1.0
        self._view_totals[view] += 1.0

    # -- baseline warmup ----------------------------------------------------
    def observe_baseline(self, event) -> None:
        """Fold a known-benign training event into the baseline (no scoring)."""
        tick = self._tick_of(event)
        if tick is None:
            return
        # Delegate to _absorb: one implementation of the baseline update, so a
        # change to the sufficient statistics cannot miss this path.
        for view, edge in self.edges_for(event):
            self._absorb(view, edge, tick, score=0.0)

    # -- ticks --------------------------------------------------------------
    def _tick_of(self, event) -> Optional[int]:
        if event.event_time is None:
            return None
        tick = int(event.event_time.timestamp() // self.config.tick_seconds)
        if tick > self._global_tick:
            self._global_tick = tick
            self._ticks_seen += 1
        return tick


def _norm(v) -> str:
    if v is None:
        return ""
    return str(v).strip().lower()
