import pytest

from pyvpn import constants as c


def test_numbering_matches_plan() -> None:
    assert c.policy_table(3) == 1003
    assert c.policy_rule_pref(3) == 5203
    assert c.dns_stub_port(3) == 5303
    assert c.policy_cgroup(3) == "pyvpn.slice/p-3"
    assert c.policy_mark(3) & c.FWMARK_MASK == c.FWMARK_BASE


@pytest.mark.parametrize("bad", [0, -1, c.MAX_POLICIES + 1])
def test_out_of_range_ids(bad: int) -> None:
    with pytest.raises(ValueError):
        c.policy_mark(bad)


def test_marks_are_unique() -> None:
    marks = {c.policy_mark(i) for i in range(1, c.MAX_POLICIES + 1)}
    assert len(marks) == c.MAX_POLICIES
