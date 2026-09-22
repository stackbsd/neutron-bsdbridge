"""Writer to apply the plan to the running kernel."""

from neutron_bsdbridge import ifconfig
from neutron_bsdbridge.constants import OWNED_GROUP
from neutron_bsdbridge.ifconfig import IFCONFIG
from neutron_bsdbridge.l2_agent import plan as plan_mod
from neutron_bsdbridge.l2_agent.pf import PFCTL, anchor_name
from neutron_bsdbridge.l2_agent.pf import kill_port_states as pf_state_kill
from neutron_bsdbridge.utils import TIMEOUT, Receipt, default_run

# destroying a held tap blocks in the ioctl until the holder exits
DESTROY_TIMEOUT = 5


def argv_for(op):
    """Return the invocation an op maps to."""
    t = type(op)
    if t is plan_mod.CreateBridge:
        return (
            IFCONFIG,
            "bridge",
            "create",
            "name",
            op.name,
            "group",
            OWNED_GROUP,
            "maxaddr",
            str(op.maxaddr),
            "up",
        )
    if t is plan_mod.CreateVlan:
        return (
            IFCONFIG,
            "vlan",
            "create",
            "vlandev",
            op.parent,
            "vlan",
            str(op.vid),
            "name",
            op.name,
            "group",
            OWNED_GROUP,
            "up",
        )
    if t is plan_mod.CreateVxlan:
        return (
            IFCONFIG,
            "vxlan",
            "create",
            "vxlanid",
            str(op.vni),
            "vxlanlocal",
            op.local,
            "vxlanremote",
            op.peer,
            "name",
            op.name,
            "group",
            OWNED_GROUP,
            "up",
        )
    if t is plan_mod.CreateTap:
        argv = [IFCONFIG, "tap", "create", "name", op.name]
        if op.description:
            argv += ["descr", op.description]
        argv += ["group", OWNED_GROUP, "up"]
        return tuple(argv)
    if t is plan_mod.AddMember:
        return (IFCONFIG, op.bridge, "addm", op.member)
    if t is plan_mod.RemoveMember:
        return (IFCONFIG, op.bridge, "deletem", op.member)
    if t is plan_mod.SetMaxaddr:
        return (IFCONFIG, op.bridge, "maxaddr", str(op.maxaddr))
    if t in (plan_mod.DestroyIface, plan_mod.DestroyBridge):
        return (IFCONFIG, op.name, "destroy")
    if t is plan_mod.LoadAnchor:
        return (PFCTL, "-a", anchor_name(op.ifname), "-f", "-")
    if t is plan_mod.ReplaceTable:
        anchor = anchor_name(op.ifname)
        if not op.members:
            return (PFCTL, "-a", anchor, "-t", op.table, "-T", "flush")
        return (PFCTL, "-a", anchor, "-t", op.table, "-T", "replace", *op.members)
    if t is plan_mod.FlushAnchor:
        return (PFCTL, "-a", anchor_name(op.ifname), "-F", "all")
    if t is plan_mod.LockMemberMac:
        # first of the three invocations apply() runs
        return (IFCONFIG, op.bridge, "static", op.member, op.mac)
    raise ValueError(f"no writer mapping for {op!r}")


class Writer:
    """Apply plans, emitting argv in dry-run and executing them otherwise."""

    def __init__(self, dry_run=True, run=default_run):
        """Wire up the run callable."""
        self.dry_run = dry_run
        self._run = run

    def _owned_by_kernel(self, name):
        """Return whether the kernel marks an interface owned, or None if absent."""
        rc, out, _err = self._run((IFCONFIG, name))
        if rc != 0:
            return None
        parsed = ifconfig.parse(out)
        iface = parsed.get(name)
        return bool(iface and iface.is_owned)

    def apply(self, op):
        """Apply one op and return its Receipt."""
        argv = argv_for(op)
        if self.dry_run:
            return Receipt(op=op, argv=argv, executed=False, ok=True)

        if isinstance(op, plan_mod.LockMemberMac):
            for extra in (
                (IFCONFIG, op.bridge, "static", op.member, op.mac),
                (IFCONFIG, op.bridge, "ifmaxaddr", op.member, "1"),
                (IFCONFIG, op.bridge, "sticky", op.member),
            ):
                rc, _out, err = self._run(extra)
                if rc != 0:
                    return Receipt(
                        op=op,
                        argv=extra,
                        executed=True,
                        ok=False,
                        note=(err or "").strip(),
                    )
            return Receipt(
                op=op,
                argv=argv,
                executed=True,
                ok=True,
                note="static + ifmaxaddr 1 + sticky",
            )

        if isinstance(op, plan_mod.FlushAnchor):
            # pfctl -F can exit nonzero after flushing so re-read instead
            self._run(argv)
            pf_state_kill(op.ifname, self._run)
            rc, out, err = self._run((PFCTL, "-a", anchor_name(op.ifname), "-sr"))
            if rc != 0 or not (out or "").strip():
                return Receipt(op=op, argv=argv, executed=True, ok=True)
            return Receipt(
                op=op,
                argv=argv,
                executed=True,
                ok=False,
                note="anchor still has content after flush",
            )

        if isinstance(op, plan_mod.LoadAnchor):
            rc, _out, err = self._run(argv, input=op.text)
            if rc != 0:
                return Receipt(
                    op=op, argv=argv, executed=True, ok=False, note=(err or "").strip()
                )
            # rule changes never touch established states
            killed = pf_state_kill(op.ifname, self._run)
            return Receipt(
                op=op,
                argv=argv,
                executed=True,
                ok=True,
                note=f"cfg:{op.cfg_hash}, {killed} state(s) killed",
            )

        is_destroy = isinstance(op, (plan_mod.DestroyIface, plan_mod.DestroyBridge))
        if is_destroy:
            # re-check against the kernel, not the plan, before the one
            # irreversible op
            owned = self._owned_by_kernel(op.name)
            if owned is None:
                return Receipt(
                    op=op, argv=argv, executed=False, ok=True, note="already absent"
                )
            if not owned:
                return Receipt(
                    op=op,
                    argv=argv,
                    executed=False,
                    ok=False,
                    note=f"REFUSED: kernel does not mark {op.name} as owned",
                )
            rc, _out, err = self._run(argv, timeout=DESTROY_TIMEOUT)
            if rc == TIMEOUT:
                return Receipt(
                    op=op,
                    argv=argv,
                    executed=True,
                    ok=False,
                    parked=True,
                    note="destroy blocked (interface held open)",
                )
        else:
            rc, _out, err = self._run(argv)

        if rc != 0:
            return Receipt(
                op=op, argv=argv, executed=True, ok=False, note=(err or "").strip()
            )
        return Receipt(op=op, argv=argv, executed=True, ok=True)

    def apply_plan(self, the_plan):
        """Apply every op in plan order without stopping early."""
        return [self.apply(op) for op in the_plan.ops]
