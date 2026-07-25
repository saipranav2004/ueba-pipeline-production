"""Streaming authentication-graph anomaly detector.

Detection substrate for the lateral-movement / credential-abuse attack class,
where the signal is a *relationship* (who authenticated to what, from where)
rather than a per-entity feature histogram. Each authentication event is
projected onto directed edges of an identity graph and scored online.

The signal is edge surprise: how improbable a (principal -> resource)
relationship is under the estate's learned access distribution, graded in nats
rather than flagged as novel or not. This generalises the "New Authentication"
filter of Bowman et al., "Detecting Lateral Movement in Enterprise Computer
Networks with Unsupervised Graph AI" (RAID 2020), which reported ~85% TPR at
0.9% FPR on LANL -- far above non-graph ML on the same data.

A microcluster (MIDAS) term over per-tick repetition was measured against this
model and removed: it cost ten detections and 0.7 additional false-positive
entities a day, because benign repetition is common and a raw repeat count fires
on it. What remains of that idea is the non-absorption rule below.

Scoring is read-only with respect to attack absorption (MIDAS-F rationale,
Bhatia et al. TKDD 2022): a flagged edge is not folded into the baseline, so an
attacker cannot normalise their own behaviour by repetition.
"""

from __future__ import annotations

import bisect
import math
from collections import defaultdict
from dataclasses import dataclass, field

# Windows logon types that represent a *remote* authentication (an edge between
# two hosts) rather than a local/console session. 3 = network, 10 = remote
# interactive (RDP). Interactive (2) and service (5) logons are same-host and
# are ignored for the host->host projection.
REMOTE_LOGON_TYPES = {"3", "10"}

# Which views belong to which QUEUE. This split is measured, not stylistic.
#
# `proc_exec` (account -> program executed) solves NTDS extraction outright --
# 0/2 to 2/2 -- because that attack leaves no other relational trace. But run
# inside the relational queue's shared alert budget it takes the headline from
# 54/60 to 49/60, collapsing Kerberoasting (7/8 -> 3/8) and AS-REP roasting
# (5/6 -> 2/6): it is a high-volume view, so it competes for queue slots in every
# cell it touches and displaces the narrower Kerberos evidence.
#
# That is the fourth independent measurement of the same law (`src_dst`, a volume
# signal, process lineage, and now this), and the resolution is the one the others
# arrived at: give it its own queue and its own budget rather than dropping it.
# `share` (account -> file share) is the one view ever added to this queue that
# cost it nothing: the headline stayed at exactly 54/60 @ 3.19 FP/day over the
# same six seeds while share-scope abuse went 0/6 -> 6/6. It is admissible where
# `reg` and `pipe` were not because of its edge geometry -- routine share access
# is department-keyed, so an account touches a mean of 1.00 distinct shares and a
# second one is maximally surprising.
RELATIONAL_VIEWS = frozenset(
    {"user_src", "proc_access", "kerb_ctx", "tgs_enc", "dir_op", "share"})
EXECUTION_VIEWS = frozenset({"proc_exec"})


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


def _build_index(marg: dict[str, float]) -> tuple:
    """Sorted marginal counts plus prefix sums of ``count + 1``.

    ``count + 1`` because pi_b' = (c_b' + 1) / denom -- the +1 is the uniform
    Dirichlet pseudo-count, so summing (count + 1) and scaling once at the end is
    the same arithmetic as summing each pi separately, with one division instead
    of one per outcome.

    Two properties make a plain running sum the right accumulator here, where the
    scan path needs ``math.fsum(sorted(...))``. The array is sorted, so the order
    is canonical rather than whatever order a dict happens to be in -- which
    matters, because a bundle reloaded from JSON rebuilds its dicts differently
    and a few-ULP difference there was once enough to turn a p of exactly 1.0 into
    0.999999999 and invent an alert. And every count is an integer-valued float
    (they are only ever incremented by 1.0), so partial sums stay exact integers
    well inside 2**53 for any estate this will see.
    """
    counts = sorted(marg.values())
    prefix = [0.0]
    running = 0.0
    for i, c in enumerate(counts, start=1):
        running += c
        prefix.append(running + i)
    return counts, prefix


def _pipe_name(value) -> str:
    """Bare pipe name, with the ``\\\\.\\pipe\\`` prefix and host form removed.

    Sysmon writes the local form; a remote pipe arrives as ``\\\\HOST\\pipe\\name``.
    Both name the same resource, and keying on the raw string would make every
    remote use of a familiar pipe look novel.
    """
    if not value:
        return ""
    p = str(value).replace("/", "\\").strip().lower()
    marker = "\\pipe\\"
    i = p.find(marker)
    if i >= 0:
        p = p[i + len(marker):]
    return p.strip("\\")


# How much of a registry path identifies a *location* rather than an individual
# value. Three components below the hive keeps
# ``hklm\system\currentcontrolset\services`` distinct from
# ``hklm\software\microsoft\windows`` while collapsing the per-application leaf
# churn that would otherwise make every write novel.
_REGISTRY_CLASS_DEPTH = 3


def _registry_class(value) -> str:
    """Hive plus the first few path components of a registry target."""
    if not value:
        return ""
    parts = [p for p in str(value).replace("/", "\\").strip().lower().split("\\") if p]
    if not parts:
        return ""
    return "\\".join(parts[: 1 + _REGISTRY_CLASS_DEPTH])


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
class AuthGraphConfig:
    """Configuration for the graded edge-surprise scorer.

    Edge anomaly is graded surprise in nats, not a novelty flag. There is no
    constant "score for a novel edge": a first-time-seen edge is scored by how
    improbable it is under the estate's learned access distribution, which is
    what lets one threshold separate routine churn from a genuine first contact.
    """

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
    enabled_views: frozenset | None = None


@dataclass
class AuthGraphAnomalyDetector:
    """Online edge-anomaly scorer over the authentication graph.

    Maintains, per edge *projection*, decayed counters and a seen-set. Call
    :meth:`score_event` for each normalized auth event in time order. The score
    is the max anomaly over the event's projections; ``absorb`` folds the event
    into the baseline unless it looks anomalous.
    """

    config: AuthGraphConfig = field(default_factory=AuthGraphConfig)
    # Per (view, edge) observation count — the c_ab the Dirichlet conditional
    # needs. A plain float per edge: the burst term that once tracked per-tick
    # repetition here was measured and removed (see module docstring), leaving the
    # cumulative count as the only per-edge statistic scoring reads.
    _edges: dict[str, dict[tuple[str, str], float]] = field(
        default_factory=lambda: defaultdict(dict))
    # Principals (edge source) seen per view during baseline. Used to gate
    # novelty for views where entities have a dense baseline: a *change* for a
    # known entity is meaningful, its first-ever appearance is not.
    _principals: dict[str, set] = field(default_factory=lambda: defaultdict(set))
    # Sufficient statistics for the Dirichlet-smoothed conditional
    # P(dst | src) = (c_sd + alpha * pi_d) / (n_s + alpha).
    # All three are plain counters: O(1) update, streaming-safe, no retraining.
    # Plain dicts rather than a nested defaultdict, so the state serialises to an
    # explicit schema without a factory the loader would have to reconstruct.
    _dst_counts: dict[str, dict[str, float]] = field(default_factory=dict)
    _src_counts: dict[str, dict[str, float]] = field(default_factory=dict)
    _src_totals: dict[str, dict[str, float]] = field(default_factory=dict)
    _dst_totals: dict[str, dict[str, float]] = field(default_factory=dict)
    _view_totals: dict[str, float] = field(default_factory=lambda: defaultdict(float))
    # Prefix-sum index over each marginal, built on demand by :meth:`freeze` and
    # discarded by :meth:`_absorb`. Derived state only -- never serialised, and
    # rebuilt from the counters above. See ``_directional_pvalue``.
    _pvalue_index: dict[tuple[str, str], tuple] = field(default_factory=dict)
    # Adjacency of the edge table, in both directions, so the small set of
    # neighbours a principal actually has can be enumerated without scanning the
    # estate. Also derived; also rebuilt rather than stored.
    _adj: dict[tuple[str, str], dict[str, dict[str, float]]] = field(default_factory=dict)

    # -- eq. (2) acceleration -----------------------------------------------
    def freeze(self) -> AuthGraphAnomalyDetector:
        """Build the indexes that make the predictive p-value sub-linear.

        The Heard & Rubin-Delanchy sum runs over every outcome at least as
        improbable as the realised one, so written directly it scans the view's
        whole marginal. In the reverse direction that marginal is the set of
        *principals*, which by definition grows with the estate -- measured at
        260 sources for 265 employees and 2,031 for 2,036, making per-event
        scoring O(identities) and a scoring run quadratic. Measured end to end:
        2.2s at 265 employees, 97.9s at 2,036.

        The sum decomposes exactly. For any outcome the source has never taken,
        ``a*_b' = alpha * pi_b'``, which is strictly increasing in that outcome's
        marginal count -- so "at least as improbable" becomes a threshold on the
        count, answerable with one binary search against a sorted array and its
        prefix sums. Only the source's own neighbours, a set bounded by its
        working set rather than by the estate, need individual treatment.

        Valid until the next :meth:`_absorb`. Scoring does not absorb, so a batch
        run builds this once; the streaming path keeps the direct scan, which is
        cheaper than rebuilding an index per event.
        """
        self._pvalue_index.clear()
        self._adj.clear()
        for view, edges in self._edges.items():
            fwd: dict[str, dict[str, float]] = {}
            rev: dict[str, dict[str, float]] = {}
            for (s, d), c in edges.items():
                fwd.setdefault(s, {})[d] = c
                rev.setdefault(d, {})[s] = c
            self._adj[(view, "dst")] = fwd    # forward: key is the source
            self._adj[(view, "src")] = rev    # reverse: key is the destination
        for view, marg in self._dst_counts.items():
            self._pvalue_index[(view, "dst")] = _build_index(marg)
        for view, marg in self._src_counts.items():
            self._pvalue_index[(view, "src")] = _build_index(marg)
        return self

    # -- edge extraction ----------------------------------------------------
    def edges_for(self, event) -> list[tuple[str, tuple[str, str]]]:
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
        out: list[tuple[str, tuple[str, str]]] = []

        if et.startswith("4624") or et.startswith("4625"):
            logon_type = str(f.get("logon_type") or "")
            if logon_type not in REMOTE_LOGON_TYPES:
                return out
            user = _norm(f.get("target_user_name"))
            src = _source_identity(f)
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
        elif et == "sysmon_1":
            # (account -> program it executed). Keyed on the IDENTITY, not the host.
            #
            # A previous `rare_proc` view keyed this on (host -> image) and was
            # removed after detecting nothing in any configuration. That is a
            # different question: "is this program rare on this machine?" On a
            # domain controller the credential-extraction tools (ntdsutil,
            # vssadmin) run legitimately, so the host-keyed form has no signal by
            # construction -- which is exactly why NTDS extraction was undetectable.
            #
            # "Has THIS ACCOUNT ever run this program?" is the identity-centric
            # question the rest of the engine asks, and it is the one that
            # separates an administrator doing maintenance from an administrator's
            # credential being used to dump the directory. No tool list, no
            # allow/deny: novelty and rarity decide, as in every other view.
            user = _norm(f.get("user_norm") or f.get("user"))
            image = _basename(f.get("image"))
            if user and image and not user.endswith("$"):
                out.append(("proc_exec", (user, image)))
        elif et in ("sysmon_17", "sysmon_18"):
            # (account -> named pipe). A named pipe is the primary IPC mechanism
            # for PsExec-class execution and for Cobalt Strike's beacon, so the
            # published detections are lists of known-bad pipe names. This engine
            # cannot use a name list and does not need one: a tool's pipe is novel
            # FOR THAT ACCOUNT by construction, and novelty is what is already
            # measured. The random-suffix pipes that defeat a static list are the
            # easiest case here, not the hardest.
            user = _norm(f.get("user_norm") or f.get("user"))
            pipe = _pipe_name(f.get("pipe_name"))
            if user and pipe and not user.endswith("$"):
                out.append(("pipe", (user, pipe)))
        elif et in ("sysmon_12", "sysmon_13"):
            # (account -> registry location class). Keyed on a truncated path, for
            # exactly the reason DIR_OP_CLASS is keyed on the operation: the raw
            # TargetObject is near-unique per event (every application writes its
            # own values all day), so novelty over it would be permanent noise.
            # The truncation is generic -- hive plus three components -- and
            # deliberately carries no list of "persistence locations", which would
            # be a signature wearing a hash table.
            user = _norm(f.get("user_norm") or f.get("user"))
            key = _registry_class(f.get("target_object"))
            if user and key and not user.endswith("$"):
                out.append(("reg", (user, key)))
        elif et in ("5140", "5145"):
            # (account -> file share). The only telemetry that says which identity
            # reached which share, which is the relationship both insider data
            # staging and share-based lateral movement create and that no other
            # view sees: a logon to a file server is a `user_src` edge whether the
            # account then read its own team's folder or the finance archive.
            actor = _norm(f.get("subject_user_name"))
            share = _norm(f.get("share_name"))
            if actor and share and not actor.endswith("$"):
                out.append(("share", (actor, share)))
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
    def score_event_views(self, event, absorb: bool = True) -> list[tuple[str, float]]:
        """Return ``[(view, surprise), ...]`` for every edge this event projects.

        Each view is scored independently so its surprise can be calibrated
        against that view's own benign null (see engine.py): a relationship type
        with a structurally high or churny benign baseline is thereby contained
        to its own view rather than setting the bar for every other view.

        ``absorb`` folds each edge into the baseline unless it looks anomalous.
        Repetition within a window is deliberately not scored: a MIDAS-style burst
        term over it was measured and removed (see module docstring), so surprise
        depends only on the cumulative access distribution, not on how many times
        an edge recurs in one batch.
        """
        if event.event_time is None:
            return []
        out: list[tuple[str, float]] = []
        for view, edge in self.edges_for(event):
            s = self._surprise(view, edge)
            if absorb:
                self._absorb(view, edge, s)
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

    def _surprise(self, view: str, edge: tuple[str, str]) -> float:
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
        c = self._edges[view].get(edge, 0.0)
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

    # -- model-based predictive p-value (Heard & Rubin-Delanchy 2016) --------
    def predictive_pvalue(self, view: str, edge: tuple[str, str]) -> float:
        """Discrete predictive p-value for this edge, from the model itself.

        Heard & Rubin-Delanchy, "Network-wide anomaly detection via the Dirichlet
        process" (IEEE ISI 2016), score each connection by the predictive
        probability of seeing an outcome *at least as improbable* as the realised
        one -- their equation (2):

            p = sum over { b' : a*_b' <= a*_b } of  a*_b' / a*

        with ``a*_b = c_ab + alpha * pi_b`` and ``a* = n_a + alpha``, i.e. exactly
        the Dirichlet-multinomial predictive this detector already maintains. Their
        method detected the LANL red team with it.

        WHY THIS EXISTS ALONGSIDE THE EMPIRICAL NULL. The shipped path turns raw
        surprise into a p-value against a *frozen empirical null*, which is floored
        at ``1/(n_benign+1)``. For a sparse view that floor dominates: ``dir_op``
        calibrates on a few dozen observations, so its smallest assertable p is
        ~0.03 and every genuinely extreme directory operation ties with every other
        at exactly that value. Measured, those ties are what make the peak-hour
        attribution degenerate -- an entity's "most anomalous window" is then picked
        arbitrarily among tied windows, often a benign one.

        This statistic has no such floor: it is computed from the model's own
        predictive distribution, so a rare operation by a rare actor can be
        assigned a probability far below what the calibration sample size would
        allow. It is naturally conservative (the paper notes the discrete p-value is
        stochastically larger than uniform), which is the right direction to err.

        Both directions are scored and the smaller taken, mirroring the ``max`` over
        the two conditionals in :meth:`_surprise`.
        """
        src, dst = edge
        fwd = self._directional_pvalue(view, src, dst, self._dst_counts,
                                       self._src_totals)
        rev = self._directional_pvalue(view, dst, src, self._src_counts,
                                       self._dst_totals)
        return min(fwd, rev)

    def _directional_pvalue(self, view: str, key_a: str, key_b: str,
                            counts_b, totals_a) -> float:
        """One conditional direction of the predictive p-value."""
        a = self.config.alpha
        marg = counts_b.get(view, {})
        if not marg:
            return 1.0
        forward = counts_b is self._dst_counts
        index = self._pvalue_index.get((view, "dst" if forward else "src"))
        if index is not None:
            return self._directional_pvalue_indexed(
                view, key_a, key_b, marg, totals_a, forward, index)
        total = self._view_totals[view]
        denom_pi = total + max(len(marg), 1)
        n_a = totals_a.get(view, {}).get(key_a, 0.0)

        # a*_b for the realised outcome. The per-edge count is only non-zero for
        # the (a, b) pair actually observed together.
        c_ab = self._edges[view].get((key_a, key_b) if counts_b is self._dst_counts
                                     else (key_b, key_a), 0.0)
        pi_b = (marg.get(key_b, 0.0) + 1.0) / denom_pi
        star_obs = c_ab + a * pi_b

        # Sum a*_b' over every outcome at least as improbable. Outcomes this source
        # has never taken contribute only alpha*pi; the handful it has taken carry
        # their counts too, so they are corrected individually.
        #
        # The summation is deliberately ORDER-INDEPENDENT and exactly rounded:
        # contributions are sorted and added with math.fsum. A plain running total
        # over dict order is not reproducible, because a bundle reloaded from JSON
        # rebuilds these dicts in a different insertion order, and the few-ULP
        # difference that follows is enough to turn a p of exactly 1.0 into
        # 0.999999999 -- which passes a `p < 1.0` filter and invents an alert that
        # the pre-save engine did not raise. Scores must not depend on whether the
        # model came from memory or from disk.
        contributions = []
        excluded = False
        for b_prime, count in marg.items():
            pi = (count + 1.0) / denom_pi
            star = a * pi
            if b_prime != key_b:
                edge_key = ((key_a, b_prime) if counts_b is self._dst_counts
                            else (b_prime, key_a))
                star += self._edges[view].get(edge_key, 0.0)
            else:
                star = star_obs
            if star <= star_obs:
                contributions.append(star)
            else:
                excluded = True
        if not excluded:
            # The observed outcome is the most probable one, so every outcome is
            # at least as improbable and the mass sums to exactly (n_a + alpha).
            # Returning the computed ratio instead would give 0.9999999999999999
            # from the pi normalisation's rounding -- and the engine treats any
            # p < 1.0 as evidence, so the most routine behaviour an identity has
            # would open a detection cell. Exactly 1.0 means "no evidence".
            return 1.0
        total_mass = math.fsum(sorted(contributions))
        return float(min(max(total_mass / (n_a + a), 1e-12), 1.0))

    def _directional_pvalue_indexed(self, view: str, key_a: str, key_b: str,
                                    marg, totals_a, forward: bool,
                                    index) -> float:
        """The same statistic as ``_directional_pvalue``, without the full scan.

        Outcomes split into two groups. Those ``key_a`` has never taken carry
        ``a*_b' = alpha * pi_b'``, which is increasing in the outcome's marginal
        count, so "at least as improbable as the realised outcome" is the count
        threshold solved for below and the included mass is one prefix-sum lookup.
        Those ``key_a`` HAS taken carry their edge count too and are corrected
        individually -- there are as many of them as the principal's working set,
        which measurement shows is bounded rather than growing with the estate.
        """
        counts_sorted, prefix = index
        a = self.config.alpha
        n_outcomes = len(counts_sorted)
        denom_pi = self._view_totals[view] + max(n_outcomes, 1)
        n_a = totals_a.get(view, {}).get(key_a, 0.0)
        neighbours = self._adj.get((view, "dst" if forward else "src"), {}).get(key_a, {})

        c_ab = neighbours.get(key_b, 0.0)
        pi_b = (marg.get(key_b, 0.0) + 1.0) / denom_pi
        star_obs = c_ab + a * pi_b

        # alpha * (count + 1) / denom_pi <= star_obs  <=>  count <= threshold.
        threshold = star_obs * denom_pi / a - 1.0
        k = bisect.bisect_right(counts_sorted, threshold)
        mass_plus_one = prefix[k]          # sum of (count + 1) over those k outcomes
        n_above = n_outcomes - k           # outcomes excluded on the base term alone

        # Everything needing individual treatment: the principal's neighbours, and
        # the realised outcome (which contributes star_obs by definition).
        special = dict(neighbours)
        special.setdefault(key_b, c_ab)
        contributions = []
        excluded = False
        for b_prime, c in special.items():
            count = marg.get(b_prime, 0.0)
            if count <= threshold:
                mass_plus_one -= count + 1.0   # retract the base-only contribution
            else:
                n_above -= 1                   # re-decided individually just below
            if b_prime == key_b:
                contributions.append(star_obs)
                continue
            star = a * (count + 1.0) / denom_pi + c
            if star <= star_obs:
                contributions.append(star)
            else:
                excluded = True
        if n_above > 0:
            excluded = True
        if not excluded:
            # Identical reasoning to the scan path: the realised outcome is the
            # most probable one, every outcome is at least as improbable, and the
            # mass is exactly (n_a + alpha). Return exactly 1.0 -- "no evidence" --
            # rather than a rounded 0.9999999999999999 that the engine would read
            # as a detection.
            return 1.0
        total_mass = a * mass_plus_one / denom_pi + math.fsum(sorted(contributions))
        return float(min(max(total_mass / (n_a + a), 1e-12), 1.0))

    def _absorb(self, view: str, edge: tuple[str, str], score: float) -> None:
        # MIDAS-F: do not let a flagged edge normalise itself into the baseline.
        if score >= self.config.absorb_surprise:
            return
        # Any absorbed edge moves a marginal, so the prefix-sum index built by
        # freeze() no longer describes the model. Dropping it returns scoring to
        # the direct scan, which is the correct behaviour for the streaming path:
        # rebuilding a sorted index per event costs more than the scan it saves.
        if self._pvalue_index:
            self._pvalue_index.clear()
            self._adj.clear()
        self._principals[view].add(edge[0])
        self._edges[view][edge] = self._edges[view].get(edge, 0.0) + 1.0
        for store, k in ((self._dst_counts, edge[1]), (self._src_counts, edge[0]),
                         (self._src_totals, edge[0]), (self._dst_totals, edge[1])):
            m = store.setdefault(view, {})
            m[k] = m.get(k, 0.0) + 1.0
        self._view_totals[view] += 1.0

    # -- baseline warmup ----------------------------------------------------
    def observe_baseline(self, event) -> None:
        """Fold a known-benign training event into the baseline (no scoring)."""
        if event.event_time is None:
            return
        # Delegate to _absorb: one implementation of the baseline update, so a
        # change to the sufficient statistics cannot miss this path.
        for view, edge in self.edges_for(event):
            self._absorb(view, edge, score=0.0)


def _norm(v) -> str:
    if v is None:
        return ""
    return str(v).strip().lower()
