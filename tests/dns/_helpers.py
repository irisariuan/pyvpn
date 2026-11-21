from pyvpn.config.models import LeakSettings
from pyvpn.constants import (
    dns_stub_port,
    policy_cgroup,
    policy_mark,
    policy_rule_pref,
    policy_table,
)
from pyvpn.state import AppBinding, PolicyPlan


def plan_for_dns(**leak: object) -> PolicyPlan:
    return PolicyPlan(
        policy_id=1,
        mark=policy_mark(1),
        table=policy_table(1),
        rule_pref=policy_rule_pref(1),
        route="dev",
        interface="wg-jp",
        gateway=None,
        apps=AppBinding(1, cgroup_paths=(policy_cgroup(1),)),
        dests=None,
        leak=LeakSettings.model_validate({"dns_server": "192.0.2.53", **leak}),
        dns_stub_port=dns_stub_port(1),
    )
