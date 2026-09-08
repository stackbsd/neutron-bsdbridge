"""Planner to turn desired config vs current state into actual ops."""

import dataclasses

from neutron_bsdbridge import model, pf

VXLAN_UPLINK = "vx{vni}p{idx}"


class PlanError(Exception):
    """The desired state cannot be realized as planned ops."""


@dataclasses.dataclass(frozen=True)
class Op:
    """Base of every typed op."""

    def __str__(self):
        """Render the op as its class name plus field=value pairs."""
        body = " ".join(
            f"{f.name}={getattr(self, f.name)}" for f in dataclasses.fields(self)
        )
        return f"{type(self).__name__} {body}"


@dataclasses.dataclass(frozen=True)
class CreateBridge(Op):
    """Create a bridge with the ownership group and a maxaddr limit."""

    name: str
    maxaddr: int


@dataclasses.dataclass(frozen=True)
class CreateVlan(Op):
    """Create a vlan(4) child of a trunk interface."""

    name: str
    parent: str
    vid: int


@dataclasses.dataclass(frozen=True)
class CreateVxlan(Op):
    """Create one point-to-point vxlan interface toward a peer."""

    name: str
    vni: int
    local: str
    peer: str


@dataclasses.dataclass(frozen=True)
class CreateTap(Op):
    """Create a tap interface with the ownership group."""

    name: str
    description: str


@dataclasses.dataclass(frozen=True)
class LoadAnchor(Op):
    """Load a member's rendered ruleset into its per-port anchor."""

    ifname: str
    filter: str
    text: str = dataclasses.field(default="", repr=False, compare=False)
    cfg_hash: str = ""

    def __str__(self):
        """Render the op with its filter name and cfg hash."""
        return (
            f"LoadAnchor ifname={self.ifname} "
            f"filter={self.filter or '(bind-only)'} cfg={self.cfg_hash}"
        )


@dataclasses.dataclass(frozen=True)
class ReplaceTable(Op):
    """Atomically replace one table's members in a member's anchor."""

    ifname: str
    table: str
    members: tuple


@dataclasses.dataclass(frozen=True)
class FlushAnchor(Op):
    """Flush all content from a member's anchor."""

    ifname: str


@dataclasses.dataclass(frozen=True)
class LockMemberMac(Op):
    """Lock a member to one MAC on the bridge."""

    bridge: str
    member: str
    mac: str


@dataclasses.dataclass(frozen=True)
class AddMember(Op):
    """Add an interface to a bridge."""

    bridge: str
    member: str


@dataclasses.dataclass(frozen=True)
class RemoveMember(Op):
    """Remove an interface from a bridge."""

    bridge: str
    member: str


@dataclasses.dataclass(frozen=True)
class DestroyIface(Op):
    """Destroy an owned non-bridge interface."""

    name: str


@dataclasses.dataclass(frozen=True)
class DestroyBridge(Op):
    """Destroy an owned bridge."""

    name: str


@dataclasses.dataclass(frozen=True)
class SetMaxaddr(Op):
    """Set a bridge's address-table limit."""

    bridge: str
    maxaddr: int


class Plan:
    """Ordered ops plus notes for what could not become ops."""

    def __init__(self):
        """Start with every phase and the notes empty."""
        self.creates = []
        self.removes = []
        self.adds = []
        self.destroys = []
        self.notes = []

    @property
    def ops(self):
        """Return all ops in execution order."""
        return self.creates + self.removes + self.adds + self.destroys

    @property
    def empty(self):
        """Return whether the plan has no ops."""
        return not self.ops


def uplink_names(bridge_name, bridge, config):
    """Return the derived member names a bridge's segment implies."""
    seg = bridge.segment
    if seg is None:
        return []
    if seg.vxlan is not None:
        return [
            VXLAN_UPLINK.format(vni=seg.vxlan.vni, idx=i)
            for i in range(len(seg.vxlan.peers))
        ]
    trunk = config.physnet[seg.physnet].trunk
    if seg.vlan is not None:
        name = f"{trunk}.{seg.vlan}"
        if len(name) > model.IFNAME_MAX:
            raise PlanError(
                f"derived vlan name {name!r} exceeds IFNAMSIZ. Shorten the trunk name."
            )
        return [name]
    # flat: the physnet NIC itself joins
    return [trunk]


def uplink_creates(bridge, seg, names, kernel):
    """Return ops to manufacture a segment's missing uplinks."""
    ops = []
    if seg.vxlan is not None:
        for name, peer in zip(names, seg.vxlan.peers, strict=False):
            if name not in kernel:
                ops.append(
                    CreateVxlan(
                        name=name, vni=seg.vxlan.vni, local=seg.vxlan.local, peer=peer
                    )
                )
    elif seg.vlan is not None:
        name = names[0]
        if name not in kernel:
            parent = name.rsplit(".", 1)[0]
            ops.append(CreateVlan(name=name, parent=parent, vid=seg.vlan))
    # flat: nothing to create, the NIC is attached hardware
    return ops


def pf_ops_for(mname, member, config, pf_state):
    """Return the pf-plane ops one member needs, as (load_op, table_ops)."""
    # pf_state None: the anchor loads only when the interface is manufactured
    filt = config.filter.get(member.filter) if member.filter else None
    if filt is None and member.bind is None:
        return None, []
    tables = pf.wanted_tables(filt, config)
    text, cfg_hash = pf.render(mname, filt, member.bind, tables)
    load = LoadAnchor(
        ifname=mname, filter=member.filter or "", text=text, cfg_hash=cfg_hash
    )
    if pf_state is None:
        return load, []
    state = pf_state.get(mname)
    if state is None or not state.exists or state.cfg_hash != cfg_hash:
        return load, []
    table_ops = []
    for name, wanted in sorted(tables.items()):
        have = state.tables.get(name, frozenset())
        if frozenset(wanted) != have:
            table_ops.append(
                ReplaceTable(ifname=mname, table=name, members=tuple(wanted))
            )
    return None, table_ops


def diff(config, kernel, pf_state=None):
    """Diff a desired Config against the kernel into a Plan."""
    plan = Plan()
    desired_ifaces = set()  # every non-bridge name the config claims
    early_destroys = []  # owned members evicted from live bridges

    for bname, bridge in config.bridge.items():
        seg = bridge.segment
        names = uplink_names(bname, bridge, config)
        desired_ifaces.update(names)

        # never adopt... a foreign interface under a desired name is an error
        iface = kernel.interfaces.get(bname)
        if iface is not None and not iface.is_bridge:
            raise PlanError(
                f"desired bridge {bname} exists in the kernel but is not a "
                "bridge. Remove or rename it by hand."
            )
        if iface is not None and not iface.is_owned:
            raise PlanError(
                f"desired bridge {bname} exists without the l2-neutron group. "
                "Remove or rename it by hand."
            )

        if iface is None:
            plan.creates.append(CreateBridge(name=bname, maxaddr=bridge.max_addresses))
        elif iface.maxaddr is not None and iface.maxaddr != bridge.max_addresses:
            plan.creates.append(SetMaxaddr(bridge=bname, maxaddr=bridge.max_addresses))
        if seg is not None:
            plan.creates.extend(uplink_creates(bridge, seg, names, kernel))

        current = set(kernel.members_of(bname))
        wanted = list(names)

        for mname, member in bridge.member.items():
            desired_ifaces.add(mname)
            wanted.append(mname)
            exists = mname in kernel
            load, table_ops = pf_ops_for(mname, member, config, pf_state)
            if member.type is not None:
                if exists and not kernel.interfaces[mname].is_owned:
                    raise PlanError(
                        f"desired member {mname} exists without the l2-neutron "
                        "group. Remove or rename it by hand."
                    )
                if not exists:
                    # create, load policy, then member, so the anchor exists
                    # before anything can open the tap
                    plan.adds.append(
                        CreateTap(name=mname, description=member.description)
                    )
                    if load is not None:
                        plan.adds.append(load)
                    plan.adds.append(AddMember(bridge=bname, member=mname))
                    load = None
                elif mname not in current:
                    if load is not None:
                        plan.adds.append(load)
                        load = None
                    plan.adds.append(AddMember(bridge=bname, member=mname))
            else:
                # config may precede the attached hardware
                if not exists:
                    plan.notes.append(f"{mname}: awaiting-attach ({bname})")
                    load = None
                elif mname not in current:
                    if load is not None:
                        plan.adds.append(load)
                        load = None
                    plan.adds.append(AddMember(bridge=bname, member=mname))
            # policy drift on an otherwise reconciled member
            if load is not None and pf_state is not None and exists:
                plan.adds.append(load)
            plan.adds.extend(table_ops)
            # mac lock after bind
            if (
                member.bind is not None
                and kernel.static_lock(bname, mname) != member.bind.mac
            ):
                plan.adds.append(
                    LockMemberMac(bridge=bname, member=mname, mac=member.bind.mac)
                )

        # flat uplinks are actual attached hardware
        # other uplinks either exist or need to be created
        manufactured = seg is not None and (
            seg.vlan is not None or seg.vxlan is not None
        )
        for name in names:
            if name in current:
                continue
            if manufactured or name in kernel:
                plan.adds.append(AddMember(bridge=bname, member=name))
            else:
                plan.notes.append(f"{name}: awaiting-attach ({bname})")

        # foreign members are removed (don't destroy)
        for member in current:
            if member in wanted:
                continue
            plan.removes.append(RemoveMember(bridge=bname, member=member))
            iface = kernel.interfaces.get(member)
            if iface is not None and iface.is_owned:
                early_destroys.append(member)

    # set for the gc so we only issue on destroy per interface
    queued = set()

    def destroy_once(name):
        """Queue an interface's flush and destroy at most once."""
        if name not in queued:
            queued.add(name)
            if pf_state is not None:
                state = pf_state.get(name)
                if state is not None and state.exists:
                    plan.destroys.append(FlushAnchor(ifname=name))
            plan.destroys.append(DestroyIface(name=name))

    # unwanted owned bridges take members out before bridge
    for name, iface in kernel.bridges().items():
        if iface.is_owned and name not in config.bridge:
            for member in iface.members:
                plan.removes.append(RemoveMember(bridge=name, member=member))
                m = kernel.interfaces.get(member)
                if m is not None and m.is_owned:
                    destroy_once(member)
            queued.add(name)
            plan.destroys.append(DestroyBridge(name=name))

    for name in early_destroys:
        destroy_once(name)

    # clean up pf anchors
    if pf_state is not None:
        policied = set()
        for bridge in config.bridge.values():
            for mname, member in bridge.member.items():
                if member.filter or member.bind:
                    policied.add(mname)
        flushed = {
            op.ifname
            for op in plan.removes + plan.destroys
            if isinstance(op, FlushAnchor)
        }
        for ifname, state in sorted(pf_state.items()):
            if state.exists and ifname not in policied and ifname not in flushed:
                plan.removes.append(FlushAnchor(ifname=ifname))

    # clean up orphaned interfaces
    for name in kernel.owned:
        iface = kernel.interfaces.get(name)
        if iface is None or iface.is_bridge:
            continue
        if name not in desired_ifaces:
            destroy_once(name)

    return plan
