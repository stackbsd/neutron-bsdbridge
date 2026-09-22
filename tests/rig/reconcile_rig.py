#!/usr/local/bin/python3.12
"""Live reconcile rig against a real kernel."""

# run as root with the L2 agent stopped, or its orphan gc collects the
# rig's interfaces mid-run; not part of unittest discovery

import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from neutron_bsdbridge import ifconfig
from neutron_bsdbridge.l2_agent import model, reconcile, writer

UPLINK = sys.argv[1] if len(sys.argv) > 1 else "vtnet0"
TAP = "tap0000green-0"
BRIDGE = "green"
VLAN = f"{UPLINK}.220"

FAILS = []


def check(label, cond, detail=""):
    """Print one check result and record a failure."""
    print(f"  {label:52} {'ok' if cond else 'FAIL'} {detail}")
    if not cond:
        FAILS.append(label)


def show(result):
    """Print a reconcile result's receipts and notes."""
    for r in result.receipts:
        print("   ", r)
    for n in result.plan.notes:
        print("    note:", n)


cfg = model.Config.from_tree(
    {
        "physnet": {"phys0": {"trunk": UPLINK}},
        "filter": {
            "web": {"in": {"10": {"action": "pass", "proto": "tcp", "port": 443}}}
        },
        "bridge": {
            BRIDGE: {
                "segment": {"physnet": "phys0", "vlan": 220},
                "member": {TAP: {"type": "tap", "filter": "web", "description": "rig"}},
            }
        },
    }
)
empty = model.Config.from_tree({})
live = writer.Writer(dry_run=False)

print("== preflight: nothing owned, rig names absent ==")
pre = ifconfig.read_interfaces([BRIDGE])
check("group l2-neutron is empty", not pre.owned, pre.owned)
check("rig bridge absent", BRIDGE not in pre)

print("== reconcile #1: build ==")
r1 = reconcile.reconcile(cfg, writer=live)
show(r1)
check("all receipts ok", r1.reconciled)

print("== verify: kernel truth ==")
kernel = ifconfig.read_interfaces([BRIDGE])
br = kernel.interfaces.get(BRIDGE)
check("bridge exists and is ours", br is not None and br.is_owned)
check(
    "members are the vlan uplink and the tap",
    br is not None and set(br.members) == {VLAN, TAP},
    br and br.members,
)
check(
    "vlan uplink has vid 220 on the trunk",
    VLAN in kernel
    and kernel.interfaces[VLAN].vlan == 220
    and kernel.interfaces[VLAN].vlan_parent == UPLINK,
)
check(
    "tap is up and owned",
    TAP in kernel and kernel.interfaces[TAP].up and kernel.interfaces[TAP].is_owned,
)

print("== reconcile #2: must plan nothing ==")
r2 = reconcile.reconcile(cfg, writer=live)
check("second plan is empty", r2.plan.empty, [str(o) for o in r2.plan.ops])

print("== parking: teardown while a consumer holds the tap ==")
holder = subprocess.Popen(
    [
        sys.executable,
        "-c",
        f'import os,time; fd=os.open("/dev/{TAP}", os.O_RDWR); time.sleep(30)',
    ]
)
time.sleep(1)
r3 = reconcile.reconcile(empty, writer=live)
show(r3)
check("the held tap parked", len(r3.parked) == 1 and r3.parked[0].op.name == TAP)
check("everything else proceeded", all(r.ok for r in r3.receipts if not r.parked))
holder.terminate()
holder.wait()
time.sleep(1)

print("== reconcile #4: level-triggered retry finishes the teardown ==")
r4 = reconcile.reconcile(empty, writer=live)
show(r4)
check("retry reconciled", r4.reconciled)

print("== postflight: kernel clean, foreign bridges untouched ==")
post = ifconfig.read_interfaces([BRIDGE])
check("rig bridge gone", BRIDGE not in post)
check("vlan uplink gone", VLAN not in post)
check("tap gone", TAP not in post)
check("group l2-neutron empty again", not post.owned, post.owned)
r5 = reconcile.reconcile(empty, writer=live)
check("empty against clean kernel plans nothing", r5.plan.empty)

print(f"\nRIG {'PASSED' if not FAILS else f'FAILED: {FAILS}'}")
sys.exit(1 if FAILS else 0)
