"""
NetBuilder Pro — MCP Server (mcp_server.py)
════════════════════════════════════════════
FastMCP server exposing all network operations as MCP tools.
Claude calls these tools to orchestrate the full analysis pipeline.

Transport: stdio (local) or streamable HTTP (remote)
Tools:
  netbuilder_connect          — connect to device (Telnet/SSH)
  netbuilder_genie_learn      — device.learn() → structured JSON
  netbuilder_genie_parse      — device.parse() → structured JSON
  netbuilder_execute_cli      — raw CLI execute
  netbuilder_genie_diff       — Diff(pre, post) → added/removed/modified
  netbuilder_take_snapshot    — capture full pre/post protocol state
  netbuilder_extract_inventory— build inventory from raw twin
  netbuilder_build_topology   — build physical+logical topology
  netbuilder_disconnect       — disconnect from device

Usage:
    python mcp_server.py                    # stdio (for Claude Desktop / CLI)
    python mcp_server.py --http             # streamable HTTP on port 8010
"""

from __future__ import annotations
import os, json, time, re, traceback
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager

from pydantic import BaseModel, Field, ConfigDict
from mcp.server.fastmcp import FastMCP

# ── pyATS / Genie / Unicon ──────────────────────────────────────────────────
try:
    from genie.testbed import load as genie_load
    from genie.utils.diff import Diff
    from unicon.eal.dialogs import Dialog, Statement
    PYATS_AVAILABLE = True
except ImportError:
    PYATS_AVAILABLE = False
    print("[MCP] WARNING: pyATS/Genie not available — device tools will return mock data.")

# ── Netmiko ─────────────────────────────────────────────────────────────────
try:
    from netmiko import ConnectHandler
    NETMIKO_AVAILABLE = True
except ImportError:
    NETMIKO_AVAILABLE = False
    print("[MCP] WARNING: Netmiko not available — SSH channel unavailable.")

# ── CONFIGURATION ───────────────────────────────────────────────────────────
WINDOWS_IP   = os.environ.get("GNS3_HOST", "172.26.32.1")
GNS3_USER    = os.environ.get("GNS3_USERNAME", "admin")
GNS3_PASS    = os.environ.get("GNS3_PASSWORD", "cisco")
GNS3_SECRET  = os.environ.get("GNS3_SECRET", "cisco")

# ── Active device sessions (port → device object) ───────────────────────────
_sessions: Dict[int, Any] = {}          # pyATS sessions
_netmiko_sessions: Dict[int, Any] = {}  # Netmiko sessions
_state_snapshots: Dict[str, Any] = {}   # keyed by "port:label:feature"

# ── GNS3 dialog for initial config prompt ───────────────────────────────────
if PYATS_AVAILABLE:
    _gns3_dialog = Dialog([Statement(
        pattern=r'Would you like to enter the initial configuration dialog\? \[yes/no\]:',
        action='sendline(no)', loop_continue=True, continue_timer=False
    )])

# ── MCP Server ──────────────────────────────────────────────────────────────
mcp = FastMCP(
    "netbuilder_mcp",
    instructions=(
        "NetBuilder Pro MCP server for Cisco IOS/IOS-XE network operations. "
        "Use netbuilder_connect first, then use genie_learn (preferred) or genie_parse "
        "for structured data collection. Always take pre/post snapshots around changes. "
        "Use netbuilder_genie_diff to compare states. Call netbuilder_disconnect when done."
    )
)

# ════════════════════════════════════════════════════════════════════════════
# INPUT MODELS
# ════════════════════════════════════════════════════════════════════════════

class ConnectInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra='forbid')
    port: int = Field(..., description="GNS3 telnet port for the target device (e.g. 5017)", ge=1, le=65535)
    channel: str = Field(default="telnet", description="Connection channel: 'telnet' (pyATS/Genie) or 'ssh' (Netmiko)")
    ssh_port: Optional[int] = Field(default=22, description="SSH port when channel='ssh'", ge=1, le=65535)
    os_type: str = Field(default="ios", description="Device OS: 'ios', 'iosxe', 'iosxr', 'nxos'")


class LearnInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra='forbid')
    port: int = Field(..., description="GNS3 telnet port for the connected device", ge=1, le=65535)
    features: List[str] = Field(
        ...,
        description=(
            "List of Genie features to learn. Supported: "
            "'interface', 'routing', 'ospf', 'bgp', 'acl', 'vrf', 'vlan', "
            "'cdp', 'lldp', 'platform', 'mpls', 'arp', 'hsrp'. "
            "Prefer learn() over parse() — it builds complete operational models."
        ),
        min_length=1
    )


class ParseInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra='forbid')
    port: int = Field(..., description="GNS3 telnet port for the connected device", ge=1, le=65535)
    command: str = Field(..., description="Cisco IOS 'show' command to parse (e.g. 'show ip ospf neighbor')", min_length=4)


class ExecuteInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra='forbid')
    port: int = Field(..., description="GNS3 telnet port for the connected device", ge=1, le=65535)
    command: str = Field(..., description="CLI command to execute and return raw text output", min_length=1)


class SnapshotInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra='forbid')
    port: int = Field(..., description="GNS3 telnet port for the connected device", ge=1, le=65535)
    label: str = Field(..., description="Snapshot label: 'pre' (before change) or 'post' (after change)")
    features: List[str] = Field(
        default=["interface", "routing", "ospf", "bgp", "acl", "vrf", "cdp"],
        description="Genie features to capture in this snapshot"
    )


class DiffInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra='forbid')
    port: int = Field(..., description="GNS3 telnet port — used to look up stored pre/post snapshots", ge=1, le=65535)
    feature: str = Field(..., description="Protocol/feature to diff: 'ospf', 'bgp', 'interface', 'routing', etc.")
    pre_label: str = Field(default="pre", description="Label of the pre-change snapshot")
    post_label: str = Field(default="post", description="Label of the post-change snapshot")


class InventoryInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra='forbid')
    port: int = Field(..., description="GNS3 telnet port — raw twin must be collected first via genie_learn", ge=1, le=65535)


class DisconnectInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra='forbid')
    port: int = Field(..., description="GNS3 telnet port to disconnect", ge=1, le=65535)
    channel: str = Field(default="all", description="Which channel to disconnect: 'telnet', 'ssh', or 'all'")


# ════════════════════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════════════════════

def _get_pyats_device(port: int):
    """Get or create a pyATS device object for the given port."""
    if not PYATS_AVAILABLE:
        raise RuntimeError("pyATS/Genie not installed. Install: pip install pyats genie")
    if port in _sessions:
        return _sessions[port]
    tb = genie_load({'devices': {'target': {
        'os': 'ios', 'type': 'router',
        'credentials': {'default': {'username': GNS3_USER, 'password': GNS3_PASS}},
        'connections': {'vty': {
            'protocol': 'telnet', 'ip': WINDOWS_IP, 'port': port,
            'settings': {'POST_CONNECTION_SLEEP_MS': 2000, 'LEARN_HOSTNAME': True, 'TERM': 'dumb'}
        }}
    }}})
    dev = tb.devices['target']
    return dev


def _safe_to_dict(obj) -> Any:
    """Recursively convert Genie objects to plain dicts."""
    if hasattr(obj, 'to_dict'):
        return obj.to_dict()
    if hasattr(obj, '__dict__'):
        return {k: _safe_to_dict(v) for k, v in obj.__dict__.items() if not k.startswith('_')}
    if isinstance(obj, dict):
        return {k: _safe_to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_safe_to_dict(i) for i in obj]
    return obj


def _snapshot_key(port: int, label: str, feature: str) -> str:
    return f"{port}:{label}:{feature}"


def _mock_learn(feature: str) -> dict:
    """Return minimal mock data when pyATS unavailable."""
    mocks = {
        "interface": {"info": {
            "Loopback0": {"oper_status": "up", "ipv4": {"9.9.0.2/32": {}}, "description": "Router-ID"},
            "GigabitEthernet0/0.23": {"oper_status": "up", "ipv4": {"9.9.23.2/24": {}}, "description": "Link to R3"},
        }},
        "ospf": {"1": {"vrf": {"default": {"area": {"0": {"interface": {
            "GigabitEthernet0/0.23": {"neighbor": {"9.9.0.3": {"state": "FULL", "address": "9.9.23.3"}}}
        }}}}}}},
        "bgp": {"instance": {}},
        "routing": {"vrf": {"default": {"address_family": {"ipv4": {"routes": {}}}}}},
        "cdp": {"index": {}},
        "vlan": {"vlans": {}},
        "acl": {},
        "vrf": {},
        "platform": {},
        "lldp": {},
    }
    return mocks.get(feature, {})


# ════════════════════════════════════════════════════════════════════════════
# MCP TOOLS
# ════════════════════════════════════════════════════════════════════════════

@mcp.tool(
    name="netbuilder_connect",
    annotations={
        "title": "Connect to Network Device",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def netbuilder_connect(params: ConnectInput) -> str:
    """Connect to a Cisco IOS/IOS-XE device via Telnet (pyATS) or SSH (Netmiko).

    IMPORTANT: Always call this before any other netbuilder tools.
    Prefer channel='telnet' for Genie learn/parse operations.
    Use channel='ssh' for direct CLI execution via Netmiko.
    Use channel='all' to connect both simultaneously.

    Args:
        params (ConnectInput): Connection parameters including port, channel, os_type.

    Returns:
        str: JSON with status, hostname, and connected channels.
    """
    result = {"port": params.port, "channel": params.channel, "status": {}}

    # ── Telnet / pyATS ──
    if params.channel in ("telnet", "all"):
        if not PYATS_AVAILABLE:
            result["status"]["telnet"] = "unavailable — pyATS not installed"
        elif params.port in _sessions and _sessions[params.port].is_connected():
            result["status"]["telnet"] = "already_connected"
            result["hostname"] = getattr(_sessions[params.port], 'hostname', 'unknown')
        else:
            try:
                dev = _get_pyats_device(params.port)
                dev.connect(log_stdout=False, dialog=_gns3_dialog, learn_hostname=True)
                dev.execute('terminal length 0')
                _sessions[params.port] = dev
                result["status"]["telnet"] = "connected"
                result["hostname"] = getattr(dev, 'hostname', 'unknown')
            except Exception as e:
                result["status"]["telnet"] = f"error: {str(e)[:200]}"

    # ── SSH / Netmiko ──
    if params.channel in ("ssh", "all"):
        if not NETMIKO_AVAILABLE:
            result["status"]["ssh"] = "unavailable — netmiko not installed"
        elif params.port in _netmiko_sessions:
            result["status"]["ssh"] = "already_connected"
        else:
            try:
                nm = ConnectHandler(
                    device_type=f"cisco_{params.os_type}",
                    host=WINDOWS_IP,
                    port=params.ssh_port,
                    username=GNS3_USER,
                    password=GNS3_PASS,
                    secret=GNS3_SECRET,
                    timeout=30,
                )
                nm.enable()
                _netmiko_sessions[params.port] = nm
                result["status"]["ssh"] = "connected"
            except Exception as e:
                result["status"]["ssh"] = f"error: {str(e)[:200]}"

    return json.dumps(result, indent=2)


@mcp.tool(
    name="netbuilder_genie_learn",
    annotations={
        "title": "Genie Learn — Full Protocol State",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
async def netbuilder_genie_learn(params: LearnInput) -> str:
    """Learn complete operational state for one or more protocols using Genie Learn API.

    PREFERRED over genie_parse for: ospf, bgp, interface, routing, acl, vrf, vlan, cdp.
    Genie Learn builds a deep operational model — not just a single command output.

    Examples:
        features=["ospf"] → full OSPF state: neighbors, areas, interfaces, timers
        features=["bgp"]  → full BGP state: neighbors, prefixes, sessions
        features=["interface", "routing", "ospf", "cdp"] → complete network snapshot

    Args:
        params (LearnInput): port and list of feature names.

    Returns:
        str: JSON dict keyed by feature name → structured operational model.
             Each feature result is a plain dict (Genie OpsObject.to_dict()).
    """
    out: Dict[str, Any] = {}

    if not PYATS_AVAILABLE:
        for feat in params.features:
            out[feat] = _mock_learn(feat)
        out["_mock"] = True
        return json.dumps(out, indent=2, default=str)

    dev = _sessions.get(params.port)
    if not dev or not dev.is_connected():
        return json.dumps({"error": f"Device on port {params.port} not connected. Call netbuilder_connect first."})

    for feat in params.features:
        try:
            learned = dev.learn(feat)
            out[feat] = _safe_to_dict(learned)
        except Exception as e:
            out[feat] = {"_error": str(e)[:200], "_feature": feat}

    return json.dumps(out, indent=2, default=str)


@mcp.tool(
    name="netbuilder_genie_parse",
    annotations={
        "title": "Genie Parse — Single Command",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
async def netbuilder_genie_parse(params: ParseInput) -> str:
    """Parse a single show command using Genie parsers → structured JSON.

    Use this for commands not covered by genie_learn, or for targeted checks.
    Supported commands: any 'show' command that Genie has a parser for.

    Examples:
        command="show ip ospf neighbor"        → neighbor table
        command="show ip bgp summary"          → BGP peer summary
        command="show ip interface brief"      → interface status
        command="show cdp neighbors detail"    → CDP adjacency detail
        command="show ip access-lists"         → ACL entries with hit counts
        command="show route-map"               → policy map details
        command="show version"                 → platform version info

    Args:
        params (ParseInput): port and show command string.

    Returns:
        str: JSON structured output from Genie parser.
    """
    if not PYATS_AVAILABLE:
        return json.dumps({"_mock": True, "command": params.command, "result": {}})

    dev = _sessions.get(params.port)
    if not dev or not dev.is_connected():
        return json.dumps({"error": f"Device on port {params.port} not connected. Call netbuilder_connect first."})

    try:
        parsed = dev.parse(params.command)
        return json.dumps(parsed, indent=2, default=str)
    except Exception as e:
        # Fallback: raw execute if parse fails
        try:
            raw = dev.execute(params.command)
            return json.dumps({"_parse_failed": str(e)[:100], "_raw_cli": raw})
        except Exception as e2:
            return json.dumps({"error": f"parse: {str(e)[:100]} | execute: {str(e2)[:100]}"})


@mcp.tool(
    name="netbuilder_execute_cli",
    annotations={
        "title": "Execute Raw CLI Command",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
async def netbuilder_execute_cli(params: ExecuteInput) -> str:
    """Execute a raw CLI command and return unstructured text output.

    Use for commands without Genie parsers, or when raw text is needed.
    For read-only commands ('show') this is safe. For config commands,
    use carefully — this executes directly on the device.

    Prefers SSH (Netmiko) channel if available, falls back to Telnet (pyATS).

    Args:
        params (ExecuteInput): port and CLI command string.

    Returns:
        str: JSON with raw_output (text), channel used, and timestamp.
    """
    channel_used = "none"
    output = ""

    # Prefer Netmiko SSH if available
    nm = _netmiko_sessions.get(params.port)
    if nm:
        try:
            output = nm.send_command(params.command, read_timeout=60)
            channel_used = "ssh_netmiko"
        except Exception as e:
            output = f"Netmiko error: {str(e)[:200]}"

    # Fallback to pyATS telnet
    if not output or output.startswith("Netmiko error"):
        dev = _sessions.get(params.port)
        if dev and dev.is_connected():
            try:
                output = dev.execute(params.command)
                channel_used = "telnet_pyats"
            except Exception as e:
                output = f"pyATS error: {str(e)[:200]}"
        elif not PYATS_AVAILABLE:
            output = f"[MOCK] {params.command} output"
            channel_used = "mock"

    return json.dumps({
        "command": params.command,
        "raw_output": output,
        "channel": channel_used,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "lines": len(output.split("\n")) if output else 0
    }, indent=2)


@mcp.tool(
    name="netbuilder_take_snapshot",
    annotations={
        "title": "Take Protocol State Snapshot",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False
    }
)
async def netbuilder_take_snapshot(params: SnapshotInput) -> str:
    """Capture a complete protocol state snapshot using Genie Learn.

    CRITICAL for simulation: take 'pre' snapshot BEFORE applying any change,
    then take 'post' snapshot AFTER. Use netbuilder_genie_diff to compare.

    Workflow:
        1. netbuilder_take_snapshot(port, label='pre', features=['ospf','bgp','routing'])
        2. [apply configuration change]
        3. netbuilder_take_snapshot(port, label='post', features=['ospf','bgp','routing'])
        4. netbuilder_genie_diff(port, feature='ospf') → exact diff

    Args:
        params (SnapshotInput): port, label ('pre'/'post'), and list of features.

    Returns:
        str: JSON with snapshot metadata and summary of captured features.
    """
    summary = {"port": params.port, "label": params.label, "features": {}}

    if not PYATS_AVAILABLE:
        for feat in params.features:
            mock = _mock_learn(feat)
            _state_snapshots[_snapshot_key(params.port, params.label, feat)] = mock
            summary["features"][feat] = {"status": "mock", "keys": list(mock.keys())}
        summary["_mock"] = True
        return json.dumps(summary, indent=2)

    dev = _sessions.get(params.port)
    if not dev or not dev.is_connected():
        return json.dumps({"error": f"Device on port {params.port} not connected. Call netbuilder_connect first."})

    for feat in params.features:
        try:
            learned = dev.learn(feat)
            learned_dict = _safe_to_dict(learned)
            _state_snapshots[_snapshot_key(params.port, params.label, feat)] = learned_dict
            summary["features"][feat] = {
                "status": "captured",
                "top_keys": list(learned_dict.keys())[:6],
                "snapshot_key": _snapshot_key(params.port, params.label, feat)
            }
        except Exception as e:
            summary["features"][feat] = {"status": f"error: {str(e)[:100]}"}

    summary["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
    return json.dumps(summary, indent=2)


@mcp.tool(
    name="netbuilder_genie_diff",
    annotations={
        "title": "Genie State Diff — Pre vs Post",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
async def netbuilder_genie_diff(params: DiffInput) -> str:
    """Compare pre-change and post-change protocol state using Genie Diff engine.

    REQUIRES: netbuilder_take_snapshot called with label='pre' and label='post'
    for the same port and feature before calling this tool.

    Genie Diff provides:
        - added: keys/values that appeared in post but not pre
        - removed: keys/values that were in pre but gone in post
        - modified: keys/values that changed between pre and post

    This is deterministic — no LLM guessing needed for config diff.

    Args:
        params (DiffInput): port, feature name, pre/post labels.

    Returns:
        str: JSON with added, removed, modified sections and a risk assessment.
    """
    pre_key  = _snapshot_key(params.port, params.pre_label,  params.feature)
    post_key = _snapshot_key(params.port, params.post_label, params.feature)

    pre_data  = _state_snapshots.get(pre_key)
    post_data = _state_snapshots.get(post_key)

    if pre_data is None:
        return json.dumps({"error": f"Pre-snapshot not found for {pre_key}. Call netbuilder_take_snapshot with label='{params.pre_label}' first."})
    if post_data is None:
        return json.dumps({"error": f"Post-snapshot not found for {post_key}. Call netbuilder_take_snapshot with label='{params.post_label}' first."})

    # ── Genie Diff ─────────────────────────────────────────────────────────
    if not PYATS_AVAILABLE:
        # Fallback: Python dict comparison
        diff_result = _python_dict_diff(pre_data, post_data)
    else:
        try:
            diff_obj = Diff(pre_data, post_data)
            diff_obj.findDiff()
            raw_diff_str = str(diff_obj)
            diff_result = _parse_genie_diff_output(raw_diff_str)
            diff_result["raw_diff"] = raw_diff_str
        except Exception as e:
            diff_result = _python_dict_diff(pre_data, post_data)
            diff_result["_genie_diff_error"] = str(e)[:200]

    # ── Risk assessment from diff ──────────────────────────────────────────
    diff_result["feature"]    = params.feature
    diff_result["port"]       = params.port
    diff_result["risk"]       = _diff_risk_assessment(diff_result, params.feature)
    diff_result["pre_label"]  = params.pre_label
    diff_result["post_label"] = params.post_label
    diff_result["timestamp"]  = time.strftime("%Y-%m-%d %H:%M:%S")

    return json.dumps(diff_result, indent=2, default=str)


@mcp.tool(
    name="netbuilder_extract_inventory",
    annotations={
        "title": "Extract Structured Inventory from Raw Twin",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
async def netbuilder_extract_inventory(params: InventoryInput) -> str:
    """Build structured inventory (interfaces, IPs, OSPF, BGP, ACL, CDP) from a collected raw twin.

    REQUIRES: netbuilder_genie_learn must have been called first for this port.
    The raw twin is stored internally keyed by port.

    Returns inventory in the standard NetBuilder format:
        interfaces[], ip_addresses[], protocols{ospf, bgp, static},
        cdp_neighbors[], lldp_neighbors[], acl[], route_maps[]

    Args:
        params (InventoryInput): port number.

    Returns:
        str: JSON structured inventory.
    """
    # Look for the most recently learned data for this port
    features_needed = ["interface", "routing", "ospf", "bgp", "cdp", "lldp", "acl"]
    raw = {}
    for feat in features_needed:
        # Check pre snapshot first (most recent learn)
        for label in ("pre", "post", "discover"):
            key = _snapshot_key(params.port, label, feat)
            if key in _state_snapshots:
                raw[feat] = _state_snapshots[key]
                break

    if not raw:
        return json.dumps({"error": f"No data found for port {params.port}. Run netbuilder_take_snapshot first."})

    # Delegate to the shared inventory extractor
    inv = _build_inventory_from_raw(raw)
    return json.dumps(inv, indent=2, default=str)


@mcp.tool(
    name="netbuilder_disconnect",
    annotations={
        "title": "Disconnect from Device",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
async def netbuilder_disconnect(params: DisconnectInput) -> str:
    """Disconnect from a device and clean up session resources.

    Always call this when you are done with a device to free up resources.

    Args:
        params (DisconnectInput): port and channel ('telnet', 'ssh', or 'all').

    Returns:
        str: JSON with disconnection status per channel.
    """
    result = {"port": params.port, "disconnected": {}}

    if params.channel in ("telnet", "all"):
        dev = _sessions.pop(params.port, None)
        if dev:
            try:
                if dev.is_connected():
                    dev.disconnect()
                result["disconnected"]["telnet"] = "ok"
            except Exception as e:
                result["disconnected"]["telnet"] = f"error: {str(e)[:100]}"
        else:
            result["disconnected"]["telnet"] = "not_connected"

    if params.channel in ("ssh", "all"):
        nm = _netmiko_sessions.pop(params.port, None)
        if nm:
            try:
                nm.disconnect()
                result["disconnected"]["ssh"] = "ok"
            except Exception as e:
                result["disconnected"]["ssh"] = f"error: {str(e)[:100]}"
        else:
            result["disconnected"]["ssh"] = "not_connected"

    return json.dumps(result, indent=2)


# ════════════════════════════════════════════════════════════════════════════
# INTERNAL HELPERS
# ════════════════════════════════════════════════════════════════════════════

def _parse_genie_diff_output(diff_str: str) -> dict:
    """Parse Genie Diff string output into structured added/removed/modified."""
    added, removed, modified = [], [], []
    current_section = None

    for line in diff_str.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("+") and not stripped.startswith("+++"):
            added.append(stripped[1:].strip())
        elif stripped.startswith("-") and not stripped.startswith("---"):
            removed.append(stripped[1:].strip())
        elif ":" in stripped and not stripped.startswith(("+", "-")):
            modified.append(stripped)

    return {
        "added":    added,
        "removed":  removed,
        "modified": modified,
        "counts":   {"added": len(added), "removed": len(removed), "modified": len(modified)}
    }


def _python_dict_diff(pre: dict, post: dict, path: str = "") -> dict:
    """Fallback Python-based recursive dict diff when Genie unavailable."""
    added, removed, modified = [], [], []

    def _recurse(a, b, p):
        if isinstance(a, dict) and isinstance(b, dict):
            for k in set(list(a.keys()) + list(b.keys())):
                np = f"{p}.{k}" if p else str(k)
                if k not in a:
                    added.append(np)
                elif k not in b:
                    removed.append(np)
                else:
                    _recurse(a[k], b[k], np)
        elif a != b:
            modified.append(f"{p}: {str(a)[:60]} → {str(b)[:60]}")

    _recurse(pre, post, path)
    return {
        "added":    added[:50],
        "removed":  removed[:50],
        "modified": modified[:50],
        "counts":   {"added": len(added), "removed": len(removed), "modified": len(modified)},
        "_engine":  "python_fallback"
    }


def _diff_risk_assessment(diff: dict, feature: str) -> dict:
    """Assess risk level from diff results."""
    added   = diff.get("added",   [])
    removed = diff.get("removed", [])
    counts  = diff.get("counts",  {})

    risk_score = 0.0
    findings   = []

    # Neighbor drops are critical
    nbr_removed = [r for r in removed if "neighbor" in str(r).lower() or "state" in str(r).lower()]
    if nbr_removed:
        risk_score += 0.5 * min(len(nbr_removed), 4)
        findings.append(f"CRITICAL: {len(nbr_removed)} neighbor entries REMOVED — adjacencies dropped")

    # FULL state gone
    full_removed = [r for r in removed if "FULL" in str(r)]
    if full_removed:
        risk_score += 0.4
        findings.append(f"CRITICAL: FULL-state adjacency removed — routing outage likely")

    # Routes removed
    route_removed = [r for r in removed if re.search(r'\d+\.\d+\.\d+\.\d+', str(r))]
    if route_removed:
        risk_score += 0.1 * min(len(route_removed), 5)
        findings.append(f"WARNING: {len(route_removed)} route entries removed from table")

    # Interface down
    down = [r for r in modified if "down" in str(r).lower() or "admin" in str(r).lower()]
    if down:
        risk_score += 0.3
        findings.append(f"WARNING: Interface state changes detected")

    # No changes
    if counts.get("added", 0) == 0 and counts.get("removed", 0) == 0 and counts.get("modified", 0) == 0:
        return {"verdict": "NO_CHANGE", "score": 0.0, "findings": ["No state changes detected"]}

    risk_score = min(risk_score, 1.0)
    verdict = "CRITICAL" if risk_score >= 0.6 else "WARNING" if risk_score >= 0.25 else "SAFE"

    return {"verdict": verdict, "score": round(risk_score, 3), "findings": findings or ["Minor state changes detected"]}


def _build_inventory_from_raw(raw: dict) -> dict:
    """Build structured inventory from raw Genie learn data."""
    inv = {
        "interfaces": [], "ip_addresses": [],
        "protocols": {"ospf": {}, "bgp": {}, "static": [], "eigrp": {}},
        "acl": [], "route_maps": [],
        "cdp_neighbors": [], "lldp_neighbors": [],
    }

    # Interfaces
    iface_data = raw.get("interface", {}).get("info", {})
    for name, d in iface_data.items():
        ips = list(d.get("ipv4", {}).keys())
        inv["interfaces"].append({
            "name": name,
            "oper_status": d.get("oper_status", "unknown"),
            "ip_addresses": ips,
            "description": d.get("description", ""),
            "mtu": d.get("mtu", ""),
        })
        for ip_cidr in ips:
            inv["ip_addresses"].append({
                "interface": name, "ip_cidr": ip_cidr,
                "ip": ip_cidr.split("/")[0],
                "type": "loopback" if "loopback" in name.lower() else "physical",
            })

    # CDP neighbors
    cdp = raw.get("cdp", {})
    for idx, entry in cdp.get("index", {}).items():
        inv["cdp_neighbors"].append({
            "device_id": entry.get("device_id", ""),
            "local_interface": entry.get("local_interface", ""),
            "remote_interface": entry.get("port_id", ""),
            "platform": entry.get("platform", ""),
            "ip": next(iter(entry.get("management_addresses", {}).keys()), ""),
        })

    # OSPF
    ospf_nbrs = []
    for inst_name, inst in raw.get("ospf", {}).items():
        if not isinstance(inst, dict): continue
        for vrf_n, vrf_d in inst.get("vrf", {}).items():
            for area_id, area_d in vrf_d.get("area", {}).items():
                for iface_name, iface_d in area_d.get("interface", {}).items():
                    for nbr_id, nbr_d in iface_d.get("neighbor", {}).items():
                        ospf_nbrs.append({
                            "neighbor_id": nbr_id,
                            "state": nbr_d.get("state", ""),
                            "interface": iface_name,
                            "area": area_id,
                            "address": nbr_d.get("address", ""),
                        })

    inv["protocols"]["ospf"] = {
        "enabled": len(ospf_nbrs) > 0,
        "neighbors": ospf_nbrs,
    }

    return inv


# ════════════════════════════════════════════════════════════════════════════
# ENTRYPOINT
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    if "--http" in sys.argv:
        port = int(os.environ.get("MCP_PORT", 8010))
        print(f"[MCP] NetBuilder MCP Server — streamable HTTP on :{port}")
        mcp.settings.port = port
        mcp.settings.host = "0.0.0.0"
        mcp.run(transport="streamable-http")
    else:
        print("[MCP] NetBuilder MCP Server — stdio transport")
        mcp.run()
