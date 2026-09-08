"""Desired-state model dataclasses."""

import dataclasses
import re
from typing import ClassVar

MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")

# IFNAMSIZ less the NUL
IFNAME_MAX = 15

ACTION_RE = re.compile(r"pass|block")
PROTO_RE = re.compile(r"tcp|udp|icmp|icmp6")
TYPE_RE = re.compile(r"tap|epair")


class SchemaError(ValueError):
    """A tree node or field value violates the schema."""


def canonical_mac(value):
    """Lowercase and validate a MAC address string."""
    mac = str(value).strip().lower()
    if not MAC_RE.match(mac):
        raise SchemaError(f"{value!r} is not a MAC address")
    return mac


def canonical_port(value):
    """Canonicalize a port to an int or a lo-hi range string."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | str):
        raise SchemaError(f"bad port or range: {value!r}")
    if isinstance(value, int):
        lo = hi = value
    else:
        lo_s, sep, hi_s = value.partition("-")
        if not sep:
            hi_s = lo_s
        try:
            lo, hi = int(lo_s), int(hi_s)
        except ValueError:
            raise SchemaError(f"bad port or range: {value!r}") from None
    if not (1 <= lo <= 65535 and lo <= hi <= 65535):
        raise SchemaError(f"bad port or range: {value!r}")
    return lo if lo == hi else f"{lo}-{hi}"


def check_str(obj, name, min_length=None, max_length=None, pattern=None):
    """Require one field to be a string within the given bounds."""
    value = getattr(obj, name)
    label = f"{type(obj).__name__}.{name}"
    if not isinstance(value, str):
        raise SchemaError(f"{label}: expected a string, got {value!r}")
    if min_length is not None and len(value) < min_length:
        raise SchemaError(f"{label}: {value!r} is shorter than {min_length}")
    if max_length is not None and len(value) > max_length:
        raise SchemaError(f"{label}: {value!r} is longer than {max_length}")
    if pattern is not None and not pattern.fullmatch(value):
        raise SchemaError(f"{label}: {value!r} is not one of {pattern.pattern!r}")


def check_int(obj, name, ge=None, le=None):
    """Require one field to be an integer within the given bounds."""
    value = getattr(obj, name)
    label = f"{type(obj).__name__}.{name}"
    if isinstance(value, bool) or not isinstance(value, int):
        raise SchemaError(f"{label}: expected an integer, got {value!r}")
    if ge is not None and value < ge:
        raise SchemaError(f"{label}: {value!r} is less than {ge}")
    if le is not None and value > le:
        raise SchemaError(f"{label}: {value!r} is greater than {le}")


def check_str_list(obj, name):
    """Require one field to be a list of strings."""
    value = getattr(obj, name)
    label = f"{type(obj).__name__}.{name}"
    if not isinstance(value, list):
        raise SchemaError(f"{label}: expected a list, got {value!r}")
    for item in value:
        if not isinstance(item, str):
            raise SchemaError(f"{label}: expected a string, got {item!r}")


def check_model(obj, name, model_cls):
    """Require one field to be None or an instance of the given model."""
    value = getattr(obj, name)
    if value is not None and not isinstance(value, model_cls):
        raise SchemaError(
            f"{type(obj).__name__}.{name}: expected {model_cls.__name__}, got {value!r}"
        )


def check_model_map(obj, name, model_cls):
    """Require one field to map names to instances of the given model."""
    value = getattr(obj, name)
    label = f"{type(obj).__name__}.{name}"
    if not isinstance(value, dict):
        raise SchemaError(f"{label}: expected a mapping, got {value!r}")
    for key, item in value.items():
        if not isinstance(item, model_cls):
            raise SchemaError(
                f"{label}[{key!r}]: expected {model_cls.__name__}, got {item!r}"
            )


class Model:
    """Base for every model: tree construction with unknown keys refused."""

    # tree key -> field name, for keys that are not identifiers
    _aliases: ClassVar[dict] = {}
    _nested: ClassVar[dict] = {}
    _nested_map: ClassVar[dict] = {}

    @classmethod
    def from_tree(cls, data, where=None):
        """Build one model from a plain dict node."""
        where = where or cls.__name__
        if not isinstance(data, dict):
            raise SchemaError(f"{where}: expected a mapping, got {data!r}")
        fields = {f.name for f in dataclasses.fields(cls)}
        kwargs = {}
        for key, value in data.items():
            name = cls._aliases.get(key, key)
            if name not in fields:
                raise SchemaError(f"{where}: unknown key {key!r}")
            if name in kwargs:
                raise SchemaError(f"{where}: key {key!r} given twice")
            kwargs[name] = cls._child(name, value, f"{where}.{key}")
        for f in dataclasses.fields(cls):
            if (
                f.name not in kwargs
                and f.default is dataclasses.MISSING
                and f.default_factory is dataclasses.MISSING
            ):
                raise SchemaError(f"{where}: missing required key {f.name!r}")
        try:
            return cls(**kwargs)
        except ValueError as exc:
            raise SchemaError(f"{where}: {exc}") from None

    @classmethod
    def _child(cls, name, value, where):
        """Convert one tree value, building nested models."""
        sub = cls._nested.get(name)
        if sub is not None:
            return None if value is None else sub.from_tree(value, where)
        sub = cls._nested_map.get(name)
        if sub is not None:
            if value is None:
                return {}
            if not isinstance(value, dict):
                raise SchemaError(f"{where}: expected a mapping, got {value!r}")
            return {k: sub.from_tree(v, f"{where}.{k}") for k, v in value.items()}
        return value


@dataclasses.dataclass
class Physnet(Model):
    """A physical fabric: its trunk parent interface."""

    trunk: str
    description: str = ""

    def __post_init__(self):
        """Validate field shapes."""
        check_str(self, "trunk", min_length=1, max_length=IFNAME_MAX)
        check_str(self, "description")


@dataclasses.dataclass
class VxlanSegment(Model):
    """A vxlan realization: VNI, local endpoint, and peer endpoints."""

    vni: int
    local: str
    peers: list[str] = dataclasses.field(default_factory=list)

    def __post_init__(self):
        """Validate field shapes."""
        check_int(self, "vni", ge=1, le=16777215)
        check_str(self, "local")
        check_str_list(self, "peers")


@dataclasses.dataclass
class Segment(Model):
    """A bridge's segment realization: vlan, flat, or vxlan."""

    _nested: ClassVar[dict] = {"vxlan": VxlanSegment}

    physnet: str | None = None
    vlan: int | None = None
    vxlan: VxlanSegment | None = None

    def __post_init__(self):
        """Validate fields and require exactly one realization form."""
        if self.physnet is not None:
            check_str(self, "physnet")
        if self.vlan is not None:
            check_int(self, "vlan", ge=1, le=4094)
        check_model(self, "vxlan", VxlanSegment)
        if self.vxlan is not None:
            if self.physnet or self.vlan:
                raise SchemaError("a vxlan segment cannot also name a physnet or vlan")
        elif self.vlan is not None:
            if not self.physnet:
                raise SchemaError("a vlan segment needs its physnet")
        elif not self.physnet:
            raise SchemaError("a segment must be vlan, flat or vxlan")


@dataclasses.dataclass
class Bind(Model):
    """Port security for one member: the locked MAC and address."""

    mac: str
    address: str

    def __post_init__(self):
        """Canonicalize the MAC and validate the address shape."""
        self.mac = canonical_mac(self.mac)
        check_str(self, "address")


@dataclasses.dataclass
class Member(Model):
    """One bridge member, manufactured if typed, attached hardware if not."""

    _nested: ClassVar[dict] = {"bind": Bind}

    type: str | None = None
    filter: str | None = None
    description: str = ""
    bind: Bind | None = None

    def __post_init__(self):
        """Validate field shapes and the closed type vocabulary."""
        if self.type is not None:
            check_str(self, "type", pattern=TYPE_RE)
        if self.filter is not None:
            check_str(self, "filter")
        check_str(self, "description")
        check_model(self, "bind", Bind)


@dataclasses.dataclass
class Bridge(Model):
    """One bridge: segment realization plus its members."""

    _aliases: ClassVar[dict] = {"max-addresses": "max_addresses"}
    _nested: ClassVar[dict] = {"segment": Segment}
    _nested_map: ClassVar[dict] = {"member": Member}

    description: str = ""
    max_addresses: int = 2000
    segment: Segment | None = None
    member: dict[str, Member] = dataclasses.field(default_factory=dict)

    def __post_init__(self):
        """Validate fields and refuse member names longer than IFNAMSIZ."""
        check_str(self, "description")
        check_int(self, "max_addresses", ge=1)
        check_model(self, "segment", Segment)
        check_model_map(self, "member", Member)
        for name in self.member:
            if len(name) > IFNAME_MAX:
                raise SchemaError(f"member name {name!r} exceeds IFNAMSIZ")


@dataclasses.dataclass
class FilterRule(Model):
    """One first-match filter rule."""

    _aliases: ClassVar[dict] = {"from": "from_"}

    action: str
    proto: str | None = None
    port: int | str | None = None
    from_: str = "any"
    to: str = "any"

    def __post_init__(self):
        """Validate the closed vocabularies and canonicalize the port."""
        check_str(self, "action", pattern=ACTION_RE)
        if self.proto is not None:
            check_str(self, "proto", pattern=PROTO_RE)
        self.port = canonical_port(self.port)
        check_str(self, "from_")
        check_str(self, "to")


def int_rules(rules):
    """Normalize a rule table, int-ifying numbers and refusing duplicates."""
    if rules is None:
        return {}
    out = {}
    for num, rule in rules.items():
        try:
            key = int(num)
        except (TypeError, ValueError):
            raise SchemaError(f"bad rule number {num!r}") from None
        if key in out:
            raise SchemaError(f"duplicate rule number {key}")
        if not isinstance(rule, FilterRule):
            raise SchemaError(f"rule {key}: expected FilterRule, got {rule!r}")
        out[key] = rule
    return out


@dataclasses.dataclass
class Filter(Model):
    """A named filter: numbered in and out rules, in the workload's view."""

    _aliases: ClassVar[dict] = {"in": "in_"}
    _nested_map: ClassVar[dict] = {"in_": FilterRule, "out": FilterRule}

    in_: dict[int, FilterRule] = dataclasses.field(default_factory=dict)
    out: dict[int, FilterRule] = dataclasses.field(default_factory=dict)

    def __post_init__(self):
        """Normalize both rule tables."""
        self.in_ = int_rules(self.in_)
        self.out = int_rules(self.out)


@dataclasses.dataclass
class Table(Model):
    """A named address table."""

    members: list[str] = dataclasses.field(default_factory=list)

    def __post_init__(self):
        """Sort and de-duplicate members."""
        check_str_list(self, "members")
        self.members = sorted(set(self.members))


@dataclasses.dataclass
class Config(Model):
    """The whole desired document."""

    _nested_map: ClassVar[dict] = {
        "physnet": Physnet,
        "bridge": Bridge,
        "table": Table,
        "filter": Filter,
    }

    physnet: dict[str, Physnet] = dataclasses.field(default_factory=dict)
    bridge: dict[str, Bridge] = dataclasses.field(default_factory=dict)
    table: dict[str, Table] = dataclasses.field(default_factory=dict)
    filter: dict[str, Filter] = dataclasses.field(default_factory=dict)

    def __post_init__(self):
        """Refuse dangling cross-references."""
        check_model_map(self, "physnet", Physnet)
        check_model_map(self, "bridge", Bridge)
        check_model_map(self, "table", Table)
        check_model_map(self, "filter", Filter)
        for bname, bridge in self.bridge.items():
            seg = bridge.segment
            if seg and seg.physnet and seg.physnet not in self.physnet:
                raise SchemaError(f"bridge {bname}: unknown physnet {seg.physnet!r}")
            for mname, member in bridge.member.items():
                if member.filter and member.filter not in self.filter:
                    raise SchemaError(
                        f"bridge {bname} member {mname}: "
                        f"unknown filter {member.filter!r}"
                    )
        for fname, filt in self.filter.items():
            for rules in (filt.in_, filt.out):
                for num, rule in rules.items():
                    for ref in (rule.from_, rule.to):
                        if ref.startswith("@") and ref[1:] not in self.table:
                            raise SchemaError(
                                f"filter {fname} rule {num}: unknown table {ref!r}"
                            )
