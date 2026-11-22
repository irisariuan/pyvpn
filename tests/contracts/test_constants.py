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
    assert c.excluded_cgroup([3]) == "pyvpn.slice/x-4"
    assert c.excluded_cgroup([4, 1, 4]) == "pyvpn.slice/x-9"
    assert c.excluded_cgroup([1, 4], app_policy_id=2) == "pyvpn.slice/p-2/x-9"


def test_excluded_cgroup_names_are_bounded() -> None:
    every = c.excluded_cgroup(range(1, c.MAX_POLICIES + 1))
    leaf = every.rsplit("/", 1)[1]
    assert len(leaf) == c.EXCLUDED_NAME_MAX <= 255
    assert leaf == "x-" + "7" + "f" * 24


def test_excluded_cgroup_names_are_distinct() -> None:
    names = {c.excluded_cgroup([a, b]) for a in range(1, 100) for b in range(a, 100)}
    assert len(names) == 99 * 100 // 2


@pytest.mark.parametrize(
    ("ids", "app"), [([], None), ([0], None), ([c.MAX_POLICIES + 1], None), ([2], 2)]
)
def test_excluded_cgroup_rejects_bad_ids(ids: list[int], app: int | None) -> None:
    with pytest.raises(ValueError):
        c.excluded_cgroup(ids, app_policy_id=app)


@pytest.mark.parametrize(
    ("ids", "app"), [({1}, None), ({1, 4, 99}, None), ({5}, 2), (set(range(1, 100)), None)]
)
def test_excluded_policy_ids_round_trip(ids: set[int], app: int | None) -> None:
    assert c.excluded_policy_ids(c.excluded_cgroup(ids, app_policy_id=app)) == ids


@pytest.mark.parametrize(
    "path",
    [
        "pyvpn.slice/p-3",
        "pyvpn.slice/x-",
        "pyvpn.slice/x-0",
        "pyvpn.slice/x-09",
        "pyvpn.slice/x-A",
        "pyvpn.slice/x-g",
        "pyvpn.slice/p-2/x-2",  # policy 2 excluding its own app
        "pyvpn.slice/p-0/x-1",
        "pyvpn.slice/p-02/x-1",
        "pyvpn.slice/x-" + "f" * 25,  # bit beyond MAX_POLICIES
        "other.slice/x-1",
        "/pyvpn.slice/x-1",
        "pyvpn.slice/p-2/x-1/child",
    ],
)
def test_excluded_policy_ids_rejects_other_paths(path: str) -> None:
    assert c.excluded_policy_ids(path) is None
