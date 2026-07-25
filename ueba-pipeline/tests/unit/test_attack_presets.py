"""The simulator's headline attack preset must stay reproducible as the registry grows.

The documented 53/60 recall figure is measured over the ten credential-theft /
lateral-movement techniques. ``insider_data_staging`` is a different attack class
(volume abuse over an established relationship) measured as its own corpus, and it
was added to ``ATTACK_REGISTRY`` after the headline was written -- silently
changing what ``--inject-attacks all`` means and breaking reproduction of the
headline via that flag. The ``headline`` preset (attacks.HEADLINE_ATTACKS) exists
to pin the headline set explicitly; these tests guard that split so a future
technique cannot re-introduce the drift unnoticed.
"""
import sys
from pathlib import Path

# The simulator is a sibling package to ueba_pipeline and imports its own modules
# by bare name (``from attacks import ...``), so its root must be on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "enterprise_simulator"))

from attacks import (
    ATTACK_REGISTRY,
    HEADLINE_ATTACKS,
    INSIDER_CORPUS_ATTACKS,
    NHI_CORPUS_ATTACKS,
    NON_HEADLINE_ATTACKS,
)


def test_headline_and_corpora_partition_the_registry():
    """Every registered attack is in exactly one of headline / separate corpora."""
    headline, corpora = set(HEADLINE_ATTACKS), set(NON_HEADLINE_ATTACKS)
    assert headline.isdisjoint(corpora)
    assert headline | corpora == set(ATTACK_REGISTRY)


def test_separately_measured_corpora_are_excluded_from_headline():
    """Each corpus is measured on its own, never inside the headline total.

    Both are invisible to a purely relational detector by construction, so scoring
    them in the headline would understate a figure measuring a different capability.
    """
    for attack, corpus in (("insider_data_staging", INSIDER_CORPUS_ATTACKS),
                           ("insider_share_exfiltration", INSIDER_CORPUS_ATTACKS),
                           ("nhi_schedule_hijack", NHI_CORPUS_ATTACKS)):
        assert attack in ATTACK_REGISTRY        # still injectable via `all`
        assert attack in corpus
        assert attack not in HEADLINE_ATTACKS


def test_the_two_insider_sub_classes_stay_distinct():
    """Rate abuse and scope abuse are different threats and different instruments.

    `insider_data_staging` is deliberately novelty-free -- own account, own
    workstation, own file server -- because that is what proves the volume
    instrument works. `insider_share_exfiltration` is the opposite: ordinary
    volume, but a share the account has never touched. Merging them would leave
    nothing measuring either capability on its own, so they are asserted to be two
    registered attacks rather than one parameterised one.
    """
    assert {"insider_data_staging", "insider_share_exfiltration"} <= set(INSIDER_CORPUS_ATTACKS)
    assert ATTACK_REGISTRY["insider_data_staging"] is not \
        ATTACK_REGISTRY["insider_share_exfiltration"]


def test_headline_covers_the_ten_documented_techniques():
    """The exact ten techniques docs/evaluation.md reports 53/60 over."""
    assert set(HEADLINE_ATTACKS) == {
        "pass_the_hash", "kerberoasting", "password_spray", "dcsync",
        "asrep_roasting", "lsass_dump", "golden_ticket", "silver_ticket",
        "ntds_dump", "account_manipulation",
    }
