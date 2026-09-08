"""pf renderer and reader."""

import hashlib
import re

from neutron_bsdbridge.utils import default_runner

PFCTL = "/sbin/pfctl"

ANCHOR_PREFIX = "l2-neutron/port/"

# config direction from the workload's view
# pf's is the host side of the tap
DIRECTION = {"in": "out", "out": "in"}

CFG_RE = re.compile(r'label "l2-neutron:cfg:(?P<hash>[0-9a-f]{16})"')
STATE_HEAD_RE = re.compile(r"^(?P<ifname>\S+) ")
STATE_ID_RE = re.compile(r"^\s+id: (?P<id>[0-9a-f]+) ")


def state_label(ifname):
    """Return the label every pass rule on a port carries."""
    return f"l2-neutron:{ifname}"


def anchor_name(ifname):
    """Return the per-port anchor name for one interface."""
    return ANCHOR_PREFIX + ifname


def render_rule(ifname, direction, rule):
    """Render one filter rule into a single pf rule line."""
    pf_dir = DIRECTION[direction]
    parts = [
        rule.action if rule.action == "pass" else "block drop",
        pf_dir,
        "quick",
        "on",
        ifname,
    ]
    body = []
    if rule.proto:
        # pf refuses a family/proto mismatch and fails the whole anchor load
        family = "inet6" if rule.proto == "icmp6" else "inet"
        body += [family, "proto", rule.proto]
    src = rule.from_
    dst = rule.to
    if src.startswith("@"):
        src = f"<{src[1:]}>"
    if dst.startswith("@"):
        dst = f"<{dst[1:]}>"
    if rule.proto or src != "any" or dst != "any" or rule.port:
        body += ["from", src, "to", dst]
        if rule.port:
            # pf spells ranges with a colon
            body += ["port", str(rule.port).replace("-", ":")]
    else:
        body += ["all"]
    parts += body
    if rule.action == "pass":
        parts += ["keep", "state", "(if-bound)", "label", f'"{state_label(ifname)}"']
    return " ".join(parts)


def tables_referenced(filt):
    """Return the table names a filter's rules reference."""
    names = set()
    if filt is None:
        return names
    for rules in (filt.in_, filt.out):
        for rule in rules.values():
            for ref in (rule.from_, rule.to):
                if ref.startswith("@"):
                    names.add(ref[1:])
    return names


def render(ifname, filt=None, bind=None, tables=None):
    """Render one member's anchor text and its cfg hash."""
    rule_lines = []

    if bind is not None:
        # must precede the source lock as DISCOVER is sourced from 0.0.0.0
        rule_lines.append(
            f"pass in quick on {ifname} inet proto udp from 0.0.0.0 "
            f"to 255.255.255.255 port 67 keep state (if-bound) "
            f'label "{state_label(ifname)}"'
        )
        rule_lines.append(f"block drop in quick on {ifname} inet from ! {bind.address}")

    if filt is not None:
        for direction, rules in (("in", filt.in_), ("out", filt.out)):
            for num in sorted(rules):
                rule_lines.append(render_rule(ifname, direction, rules[num]))

    # rendered deny tail
    rule_lines.append(f"block drop out quick on {ifname} all")
    cfg_hash = hashlib.sha256("\n".join(rule_lines).encode()).hexdigest()[:16]
    rule_lines.append(
        f'block drop in quick on {ifname} all label "l2-neutron:cfg:{cfg_hash}"'
    )

    table_lines = []
    for name in sorted(tables_referenced(filt)):
        members = (tables or {}).get(name, [])
        table_lines.append(f"table <{name}> persist {{ {', '.join(members)} }}")

    return "\n".join(table_lines + rule_lines) + "\n", cfg_hash


def wanted_tables(filt, config):
    """Return table name to canonical member list for a filter's references."""
    return {name: config.table[name].members for name in tables_referenced(filt)}


class AnchorState:
    """Kernel state for one member's anchor."""

    def __init__(self, exists, cfg_hash=None, tables=None):
        """Record existence, the loaded cfg hash, and table members."""
        self.exists = exists
        self.cfg_hash = cfg_hash
        self.tables = tables or {}


def parse_rules_hash(sr_text):
    """Parse pfctl -sr output into the loaded config hash, or None."""
    m = CFG_RE.search(sr_text or "")
    return m.group("hash") if m else None


def parse_table_show(text):
    """Parse pfctl -T show output into a frozenset of member strings."""
    return frozenset(line.strip() for line in (text or "").splitlines() if line.strip())


def read_anchor(ifname, runner=default_runner):
    """Read one anchor's state through pfctl."""
    anchor = anchor_name(ifname)
    out = runner((PFCTL, "-a", anchor, "-sr"))
    if out is None:
        return AnchorState(exists=False)
    cfg_hash = parse_rules_hash(out)
    if cfg_hash is None and not out.strip():
        return AnchorState(exists=False)
    tables = {}
    names = runner((PFCTL, "-a", anchor, "-sT"))
    for name in (names or "").split():
        members = runner((PFCTL, "-a", anchor, "-t", name, "-T", "show"))
        if members is not None:
            tables[name] = parse_table_show(members)
    return AnchorState(exists=True, cfg_hash=cfg_hash, tables=tables)


def parse_state_ids(vvss_text, ifname):
    """Parse pfctl -vvss output into the state ids bound to one interface."""
    ids = []
    current_iface = None
    for line in (vvss_text or "").splitlines():
        if line and not line[0].isspace():
            m = STATE_HEAD_RE.match(line)
            current_iface = m.group("ifname") if m else None
        elif current_iface == ifname:
            m = STATE_ID_RE.match(line)
            if m:
                ids.append(m.group("id"))
    return ids


def kill_port_states(ifname, run):
    """Kill every state bound to a port's interface and return the count."""
    # anchor-rule states carry no label pfctl -k label can match
    rc, out, _err = run((PFCTL, "-vvss"))
    if rc != 0:
        return 0
    ids = parse_state_ids(out, ifname)
    for state_id in ids:
        run((PFCTL, "-k", "id", "-k", state_id))
    return len(ids)


def read_anchors(ifnames, runner=default_runner):
    """Read the AnchorState for each named interface."""
    return {name: read_anchor(name, runner) for name in ifnames}


def list_anchors(runner=default_runner):
    """List the interfaces with a per-port anchor loaded right now."""
    # an anchor flushed empty disappears from the listing
    out = runner((PFCTL, "-a", ANCHOR_PREFIX.rstrip("/"), "-sA"))
    if out is None:
        return []
    names = []
    for line in (out or "").splitlines():
        line = line.strip()
        if line.startswith(ANCHOR_PREFIX):
            names.append(line[len(ANCHOR_PREFIX) :])
    return names
