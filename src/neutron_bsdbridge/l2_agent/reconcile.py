"""Reconcile entry point to run the read, diff, apply flow."""

import dataclasses

from neutron_bsdbridge import ifconfig
from neutron_bsdbridge.l2_agent import pf as pf_mod
from neutron_bsdbridge.l2_agent import plan as plan_mod
from neutron_bsdbridge.l2_agent import writer as writer_mod
from neutron_bsdbridge.utils import default_run


def names_to_check(config):
    """Return every interface name the config claims."""
    # uplinks too, or attached hardware reads as awaiting-attach
    names = list(config.bridge)
    for bname, bridge in config.bridge.items():
        names.extend(bridge.member)
        names.extend(plan_mod.uplink_names(bname, bridge, config))
    return names


@dataclasses.dataclass
class Result:
    """One reconcile pass: the plan, its receipts, and the kernel it saw."""

    plan: object
    receipts: list
    kernel: object

    @property
    def reconciled(self):
        """Return whether every receipt reported ok."""
        return all(r.ok for r in self.receipts)

    @property
    def parked(self):
        """Return the parked receipts."""
        return [r for r in self.receipts if r.parked]

    @property
    def failed(self):
        """Return the receipts that failed outright."""
        return [r for r in self.receipts if not r.ok and not r.parked]


def pf_scope(config, kernel):
    """Return the interfaces whose anchors a pass must look at."""
    names = set()
    for bridge in config.bridge.values():
        for mname, member in bridge.member.items():
            if member.filter or member.bind:
                names.add(mname)
    for name in kernel.owned:
        iface = kernel.interfaces.get(name)
        if iface is not None and not iface.is_bridge:
            names.add(name)
    return names


def reconcile(config, writer=None, reader=None, pf_reader=None, run=default_run):
    """Run one pass that reads the kernel, diffs, applys the plan."""
    writer = writer or writer_mod.Writer(dry_run=True)
    names = names_to_check(config)
    kernel = reader(names) if reader else ifconfig.read_interfaces(names, run)
    scope = pf_scope(config, kernel)
    if pf_reader is None:
        scope.update(pf_mod.list_anchors(run))
        pf_state = pf_mod.read_anchors(sorted(scope), run)
    else:
        pf_state = pf_reader(sorted(scope))
    the_plan = plan_mod.diff(config, kernel, pf_state=pf_state)
    receipts = writer.apply_plan(the_plan)
    return Result(plan=the_plan, receipts=receipts, kernel=kernel)
