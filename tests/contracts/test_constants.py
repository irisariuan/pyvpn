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


def test_excluded_cgroup_names() -> None:
    assert c.excluded_cgroup([3]) == "pyvpn.slice/x-3"
    assert c.excluded_cgroup([4, 1, 4]) == "pyvpn.slice/x-1-4"
    assert c.excluded_cgroup([1, 4], app_policy_id=2) == "pyvpn.slice/p-2/x-1-4"


@pytest.mark.parametrize(
    ("ids", "app"), [([], None), ([0], None), ([c.MAX_POLICIES + 1], None), ([2], 2)]
)
def test_excluded_cgroup_rejects_bad_ids(ids: list[int], app: int | None) -> None:
    with pytest.raises(ValueError):
        c.excluded_cgroup(ids, app_policy_id=app)
