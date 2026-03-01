import os, requests, json, subprocess, re, time, traceback, math, logging
from flask import Flask, request, jsonify
from flask_cors import CORS

try:
    import igraph as ig
    IGRAPH_AVAILABLE = True
except ImportError:
    IGRAPH_AVAILABLE = False

try:
    from genie.testbed import load
    from genie.utils.diff import Diff as GenieDiff
    from unicon.eal.dialogs import Dialog, Statement
    from unicon.core.errors import SubCommandFailure
    PYATS_AVAILABLE = True
except ImportError:
    PYATS_AVAILABLE = False

# ── Netmiko (SSH channel) ───────────────────────────────────────────────────
try:
    from netmiko import ConnectHandler
    NETMIKO_AVAILABLE = True
except ImportError:
    NETMIKO_AVAILABLE = False

app = Flask(__name__)
CORS(app)

# ── Suppress paramiko transport thread errors (Telnet-banner 0xff noise) ────
# paramiko logs SSHException from a background thread even when the exception
# is caught by Netmiko.  Setting CRITICAL silences the console spam without
# affecting functional error handling.
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)

# ── Per-port SSH capability cache ───────────────────────────────────────────
# Ports that responded with a Telnet IAC (0xff) instead of an SSH banner.
# Once discovered, SSH is skipped entirely for these ports — no delay, no noise.
_TELNET_ONLY_PORTS: set = set()

# ── CONFIGURATION ──────────────────────────────────────────────────────────
WINDOWS_IP  = "172.26.32.1"
OLLAMA_URL  = f"http://{WINDOWS_IP}:11434/api/generate"

# ── ANTHROPIC CLAUDE (Pipeline + Chat) ────────────────────────────────────
# Set via env var: export ANTHROPIC_API_KEY=sk-ant-...
# On-demand ops (discovery, simulate, anomalies, healing) always use Ollama
ANTHROPIC_API_KEY     = os.environ.get("ANTHROPIC_API_KEY", "")  # set via env var
CLAUDE_EXPERT_MODEL   = os.environ.get("CLAUDE_EXPERT_MODEL",   "claude-sonnet-4-6")
CLAUDE_STANDARD_MODEL = os.environ.get("CLAUDE_STANDARD_MODEL", "claude-haiku-4-5-20251001")
ANTHROPIC_API_URL     = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION     = "2023-06-01"

# ── OLLAMA (On-Demand: discovery, simulate, anomalies, healing, scan) ──────
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3")

# ── ACTIVE PROVIDER for pipeline/chat ─────────────────────────────────────
def _detect_provider():
    if ANTHROPIC_API_KEY:
        print(f"[LLM] Pipeline/Chat provider: Claude ({CLAUDE_EXPERT_MODEL})")
        return "claude"
    print(f"[LLM] Pipeline/Chat fallback: Ollama ({OLLAMA_MODEL})")
    return "local"

ACTIVE_PROVIDER = _detect_provider()

# ── USER-SELECTABLE GLOBAL LLM PROVIDER ───────────────────────────────────
_user_selected_provider = ACTIVE_PROVIDER

def _resolve_provider(request_provider: str = None) -> str:
    if request_provider and request_provider in ("claude", "local"):
        return request_provider
    if _user_selected_provider in ("claude", "local"):
        return _user_selected_provider
    return ACTIVE_PROVIDER

# ── DISK PERSISTENCE ───────────────────────────────────────────────────────
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(DATA_DIR, exist_ok=True)

def _save_to_disk(key: str, data: dict):
    """Save data as JSON to ./data/<key>.json"""
    path = os.path.join(DATA_DIR, f"{key}.json")
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        print(f"[DISK] Saved: {path}")
    except Exception as e:
        print(f"[DISK] Save error {path}: {e}")

def _load_from_disk(key: str):
    """Load JSON from ./data/<key>.json, returns None if missing."""
    path = os.path.join(DATA_DIR, f"{key}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as e:
        print(f"[DISK] Load error {path}: {e}")
        return None

def _list_disk_keys(prefix: str = ""):
    """List all JSON files in DATA_DIR optionally filtered by prefix."""
    try:
        return [f[:-5] for f in os.listdir(DATA_DIR)
                if f.endswith(".json") and f.startswith(prefix)]
    except Exception:
        return []

# ── IN-MEMORY INVENTORY (also backed to disk) ──────────────────────────────
SAVED_INVENTORY = {}   # port → {raw_twin, inventory, physical_topology, topology, timestamp}

# ── STATE SNAPSHOTS for Genie Diff (pre/post simulation) ───────────────────
STATE_SNAPSHOTS = {}   # key: "port:label:feature" → Genie learn dict

# ── NETMIKO SSH SESSIONS ────────────────────────────────────────────────────
NETMIKO_SESSIONS = {}  # port → ConnectHandler object

def _inventory_key(port) -> str:
    return f"inventory_port_{port}"

def _save_inventory(port, data: dict):
    SAVED_INVENTORY[str(port)] = data
    _save_to_disk(_inventory_key(port), data)

def _load_all_inventories():
    """Restore inventories from disk on startup."""
    for key in _list_disk_keys("inventory_port_"):
        port = key.replace("inventory_port_", "")
        if port not in SAVED_INVENTORY:
            d = _load_from_disk(key)
            if d:
                SAVED_INVENTORY[port] = d
                print(f"[STARTUP] Restored inventory for port {port} from disk.")

_load_all_inventories()

# ── GNS3 DEVICE CREDENTIALS ───────────────────────────────────────────────
GNS3_USERNAME = os.environ.get("GNS3_USERNAME", "admin")
GNS3_PASSWORD = os.environ.get("GNS3_PASSWORD", "cisco")

if PYATS_AVAILABLE:
    gns3_dialog = Dialog([Statement(
        pattern=r'Would you like to enter the initial configuration dialog\? \[yes/no\]:',
        action='sendline(no)', loop_continue=True, continue_timer=False
    )])

def get_device_obj(port):
    return load({'devices': {'target': {
        'os': 'ios', 'type': 'router',
        'credentials': {'default': {'username': GNS3_USERNAME, 'password': GNS3_PASSWORD}},
        'connections': {'vty': {'protocol': 'telnet', 'ip': WINDOWS_IP, 'port': port,
            'settings': {'POST_CONNECTION_SLEEP_MS': 2000, 'LEARN_HOSTNAME': True, 'TERM': 'dumb'}}}
    }}}).devices['target']

# ═══════════════════════════════════════════════════════════════════════════
# RATE LIMITING + TOKEN BUDGETING + FALLBACK MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════
import threading

# Anthropic free-tier / low-credit safe limits:
#   Haiku:  25 RPM, 25K TPM input, 5K TPM output  (cheapest — use for pipeline)
#   Sonnet: 5 RPM,  20K TPM input, 8K TPM output
# We use Haiku for ALL pipeline calls to minimise cost & stay under rate limits.
# If Claude balance is zero or exhausted → auto-fallback to Ollama.

CLAUDE_PIPELINE_MODEL = "claude-haiku-4-5-20251001"   # cheapest, fastest, rate-limit friendly
CLAUDE_CHAT_MODEL     = "claude-haiku-4-5-20251001"   # chat also uses Haiku to save credits

# Hard token caps — keep well inside free-tier/low-credit window
MAX_INPUT_TOKENS  = 6000   # 6K tokens for full CCIE context
MAX_OUTPUT_TOKENS = 2048   # 2K output for full CCIE analysis report

# Rate-limiter: max 1 Claude call every N seconds
CLAUDE_MIN_INTERVAL = 5.0   # 5s interval = 12 RPM (Haiku allows 25 RPM)
_claude_lock  = threading.Lock()
_last_claude_call = 0.0

# Credit/balance state — if Claude returns balance error, flip to Ollama fallback
_claude_balance_ok = True   # flips False on credit exhaustion error

def _estimate_tokens(text: str) -> int:
    """Rough token estimate: ~0.75 words per token, 5 chars per word."""
    return max(1, len(text) // 4)

def _truncate_prompt(prompt: str, max_tokens: int = MAX_INPUT_TOKENS) -> str:
    """
    Truncate prompt so estimated input tokens stay under max_tokens.
    Preserves the FIRST portion (instruction) and LAST portion (format spec),
    cutting the middle (verbose device data) which is the main source of token bloat.
    """
    estimated = _estimate_tokens(prompt)
    if estimated <= max_tokens:
        return prompt

    # Target character budget
    char_budget = max_tokens * 4
    if len(prompt) <= char_budget:
        return prompt

    # Keep first 60% and last 40% of budget, drop the middle
    keep_head = int(char_budget * 0.60)
    keep_tail = int(char_budget * 0.40)
    truncated = prompt[:keep_head] + "\n...[truncated for token budget]...\n" + prompt[-keep_tail:]
    print(f"[TOKEN] Prompt truncated: {len(prompt)} → {len(truncated)} chars "
          f"(~{estimated} → ~{_estimate_tokens(truncated)} tokens)")
    return truncated

# ── CLAUDE API CALL (rate-limited, token-budgeted) ─────────────────────────
def _call_claude(prompt: str, model: str = None, system: str = None,
                 max_tokens: int = MAX_OUTPUT_TOKENS) -> str:
    """
    Rate-limited, token-budgeted call to Anthropic Claude.
    - Enforces MIN_INTERVAL between calls (free-tier RPM safe)
    - Truncates prompts to MAX_INPUT_TOKENS
    - Caps output to MAX_OUTPUT_TOKENS
    - On credit/balance error → sets _claude_balance_ok=False so caller can fallback
    """
    global _last_claude_call, _claude_balance_ok

    if not ANTHROPIC_API_KEY:
        return "Claude Error: ANTHROPIC_API_KEY not set."

    if not _claude_balance_ok:
        return "Claude Error: credit balance exhausted — using Ollama fallback."

    # Enforce rate limit (one call per CLAUDE_MIN_INTERVAL seconds)
    with _claude_lock:
        now = time.time()
        elapsed = now - _last_claude_call
        if elapsed < CLAUDE_MIN_INTERVAL:
            wait = CLAUDE_MIN_INTERVAL - elapsed
            print(f"[RATE] Claude rate-limit wait: {wait:.1f}s")
            time.sleep(wait)
        _last_claude_call = time.time()

    # Token budget: truncate prompt + cap output
    prompt = _truncate_prompt(prompt, MAX_INPUT_TOKENS)
    safe_max_tokens = min(max_tokens, MAX_OUTPUT_TOKENS)

    chosen_model = model or CLAUDE_PIPELINE_MODEL
    headers = {
        "x-api-key":         ANTHROPIC_API_KEY,
        "anthropic-version": ANTHROPIC_VERSION,
        "content-type":      "application/json",
    }
    body = {
        "model":      chosen_model,
        "max_tokens": safe_max_tokens,
        "messages":   [{"role": "user", "content": prompt}],
    }
    if system:
        body["system"] = system

    print(f"[CLAUDE] Calling {chosen_model} | prompt~{_estimate_tokens(prompt)} tokens | max_out={safe_max_tokens}")
    try:
        r = requests.post(ANTHROPIC_API_URL, headers=headers, json=body, timeout=120)
        r.raise_for_status()
        data = r.json()
        # Log usage for monitoring
        usage = data.get("usage", {})
        print(f"[CLAUDE] Usage: in={usage.get('input_tokens','?')} out={usage.get('output_tokens','?')}")
        for block in data.get("content", []):
            if block.get("type") == "text":
                return block["text"]
        return "Claude Error: no text block in response."
    except requests.exceptions.HTTPError as e:
        err_body = {}
        try:
            err_body = r.json()
        except Exception:
            pass
        err_msg = err_body.get("error", {}).get("message", str(e))
        # Detect credit/balance errors — flip fallback flag
        if "credit balance" in err_msg.lower() or "billing" in err_msg.lower() or r.status_code in (402, 429):
            _claude_balance_ok = False
            print(f"[CLAUDE] Credit/rate error — switching to Ollama fallback: {err_msg}")
            return f"Claude Error: {err_msg}"
        return f"Claude Error: {e} — {err_msg}"
    except Exception as e:
        return f"Claude Error: {str(e)}"

# ── OLLAMA CALL ────────────────────────────────────────────────────────────
def _call_ollama(prompt: str, model: str = None, system: str = None) -> str:
    """Call local Ollama. Used for on-demand ops AND as Claude fallback.
    system: optional role/context prepended to prompt (Ollama has no native system field).
    """
    ollama_model = model or OLLAMA_MODEL
    # Prepend system context when provided (restores CCIE expert framing for Stage 5)
    if system:
        prompt = f"{system}\n\n{prompt}"
    prompt = _truncate_prompt(prompt, MAX_INPUT_TOKENS)   # same budget as Claude
    try:
        payload = {"model": ollama_model, "prompt": prompt, "stream": False}
        r = requests.post(OLLAMA_URL, json=payload, timeout=600)  # 10 min
        return r.json().get("response", "")
    except Exception as e:
        return f"Ollama Error: {str(e)}"

# ── UNIFIED call_ai() ──────────────────────────────────────────────────────
def call_ai(prompt: str, provider: str = None, model: str = None,
            system: str = None, max_tokens: int = MAX_OUTPUT_TOKENS) -> str:
    """
    Unified AI dispatcher.

    provider='claude' → Claude Haiku (rate-limited, token-budgeted)
                        auto-falls-back to Ollama on credit exhaustion
    provider='local'  → Ollama (on-demand ops: discover, simulate, anomalies, healing)
    provider=None     → uses ACTIVE_PROVIDER

    Token budget: prompts truncated to ~3K tokens, output capped at 1024 tokens.
    Rate limit: ≥12s between Claude calls (safe for 5 RPM free-tier).
    """
    global _claude_balance_ok
    resolved_provider = provider or ACTIVE_PROVIDER

    if resolved_provider == "claude":
        result = _call_claude(prompt, model=model, system=system, max_tokens=max_tokens)
        # Auto-fallback on any Claude error (credit, key, rate)
        if result.startswith("Claude Error:"):
            print(f"[FALLBACK] Claude failed → Ollama: {result[:80]}")
            return _call_ollama(prompt, model=model, system=system)
        return result
    else:
        return _call_ollama(prompt, model=model, system=system)

def get_llm_status() -> dict:
    """Return current LLM health for /health endpoint."""
    return {
        "claude_balance_ok": _claude_balance_ok,
        "claude_model":      CLAUDE_PIPELINE_MODEL,
        "ollama_model":      OLLAMA_MODEL,
        "rate_limit_interval_s": CLAUDE_MIN_INTERVAL,
        "max_input_tokens":  MAX_INPUT_TOKENS,
        "max_output_tokens": MAX_OUTPUT_TOKENS,
        "active_provider":   ACTIVE_PROVIDER,
        "selected_provider": _user_selected_provider,
        "anthropic_key_set": bool(ANTHROPIC_API_KEY),
        "netmiko_available": NETMIKO_AVAILABLE,
        "genie_diff_available": PYATS_AVAILABLE,
    }

# ══════════════════════════════════════════════════════════════════════════════
# COLLECTION — full device snapshot
# ══════════════════════════════════════════════════════════════════════════════
def collect_device(port, logs):
    """Full device collection using Genie Learn (preferred) + Genie Parse fallback + Netmiko SSH."""
    if not PYATS_AVAILABLE:
        logs.append("[COLLECT] pyATS unavailable — using mock twin.")
        return _mock_twin([])

    dev = get_device_obj(port)
    raw = {}
    try:
        dev.connect(log_stdout=False, dialog=gns3_dialog, learn_hostname=True)
        dev.execute('terminal length 0')

        # ── Genie Learn Mode (preferred) — full operational model per protocol ──
        # Updated: now includes cdp, vlan, platform in addition to core protocols
        LEARN_FEATURES = ['interface', 'routing', 'ospf', 'bgp', 'acl', 'vrf', 'cdp', 'vlan', 'platform']
        for feat in LEARN_FEATURES:
            try:
                learned = dev.learn(feat)
                raw[feat] = learned.to_dict() if hasattr(learned, 'to_dict') else _safe_to_dict_collect(learned)
                logs.append(f"[COLLECT] Learned: {feat}")
            except Exception as e:
                logs.append(f"[COLLECT] Skip learn({feat}): {str(e)[:60]}")

        # ── Genie Parse Mode — single commands not covered by learn() ──
        # CDP detail parse (fallback if learn("cdp") schema differs)
        if not raw.get("cdp") or not raw["cdp"].get("index"):
            for cmd in ['show cdp neighbors detail', 'show cdp neighbors']:
                try:
                    raw['cdp_neighbors'] = dev.parse(cmd)
                    logs.append("[COLLECT] CDP parse fallback collected.")
                    break
                except Exception:
                    pass

        # LLDP — learn() may not be available, parse is more reliable
        try:
            raw['lldp'] = dev.learn('lldp').to_dict()
            logs.append("[COLLECT] Learned: lldp")
        except Exception:
            for cmd in ['show lldp neighbors detail', 'show lldp neighbors']:
                try:
                    raw['lldp_neighbors'] = dev.parse(cmd)
                    logs.append("[COLLECT] LLDP parse fallback collected.")
                    break
                except Exception:
                    pass

        # OSPF neighbors — raw CLI text (most reliable for classic IOS/GNS3)
        for cmd in ['show ip ospf neighbor', 'show ip ospf nei']:
            try:
                raw['ospf_neighbors_raw_cli'] = dev.execute(cmd)
                logs.append(f"[COLLECT] OSPF neighbor raw CLI ({len(raw['ospf_neighbors_raw_cli'])} chars).")
                break
            except Exception as e:
                logs.append(f"[COLLECT] OSPF neighbor raw CLI skip: {str(e)[:60]}")

        # OSPF neighbor detail — Genie parsed (secondary)
        for cmd in ['show ip ospf neighbor detail', 'show ip ospf neighbor']:
            try:
                raw['ospf_neighbors_detail'] = dev.parse(cmd)
                logs.append("[COLLECT] OSPF neighbor detail (Genie parsed).")
                break
            except Exception as e:
                logs.append(f"[COLLECT] OSPF neighbor detail skip: {str(e)[:60]}")

        # OSPF database
        for cmd in ['show ip ospf database router', 'show ip ospf database']:
            try:
                raw['ospf_database'] = dev.parse(cmd)
                logs.append("[COLLECT] OSPF database collected.")
                break
            except Exception:
                pass

        # BGP summary
        for cmd in ['show ip bgp summary', 'show bgp all summary']:
            try:
                raw['bgp_summary'] = dev.parse(cmd)
                logs.append("[COLLECT] BGP summary.")
                break
            except Exception:
                pass

        # BGP neighbor detail
        for cmd in ['show ip bgp neighbors', 'show bgp neighbors']:
            try:
                raw['bgp_neighbors_detail'] = dev.parse(cmd)
                logs.append("[COLLECT] BGP neighbor detail.")
                break
            except Exception:
                pass

        # BGP routes raw
        try:
            raw['bgp_routes'] = dev.execute('show ip bgp')
            logs.append("[COLLECT] BGP routes collected.")
        except Exception:
            pass

        # Route-maps
        try:
            raw['route_maps'] = dev.parse('show route-map')
        except Exception:
            try:
                raw['route_maps_raw'] = dev.execute('show route-map')
            except Exception:
                pass

        # ACL (parsed — in case learn("acl") didn't get hit counts)
        try:
            raw['ip_access_lists'] = dev.parse('show ip access-lists')
        except Exception:
            try:
                raw['ip_access_lists_raw'] = dev.execute('show ip access-lists')
            except Exception:
                pass

        # Running config
        try:
            raw['running_config'] = dev.execute('show running-config')
            logs.append("[COLLECT] Running config collected.")
        except Exception:
            pass

        # IP interface brief
        try:
            raw['ip_interface_brief'] = dev.parse('show ip interface brief')
        except Exception:
            try:
                raw['ip_interface_brief_raw'] = dev.execute('show ip interface brief')
            except Exception:
                pass

        # ── IPv6 interface brief (spec requirement) ──
        try:
            raw['ipv6_interface_brief'] = dev.parse('show ipv6 interface brief')
        except Exception:
            try:
                raw['ipv6_interface_brief_raw'] = dev.execute('show ipv6 interface brief')
            except Exception:
                pass

        # ── MPLS (if applicable) ──
        try:
            raw['mpls'] = dev.learn('mpls').to_dict()
            logs.append("[COLLECT] Learned: mpls")
        except Exception:
            pass

        # ── ARP table ──
        try:
            raw['arp'] = dev.parse('show arp')
            logs.append("[COLLECT] ARP table collected.")
        except Exception:
            pass

    finally:
        try:
            if dev.is_connected():
                dev.disconnect()
        except Exception:
            pass

    # ── Netmiko SSH supplement (if available) ──────────────────────────────
    # SSH can reach devices that Telnet can't, and gets cleaner output on some IOS versions
    _port_key = str(port)
    if str(port) in _TELNET_ONLY_PORTS:
        logs.append(f"[COLLECT] SSH skipped — port {port} is Telnet-only (cached).")
    elif NETMIKO_AVAILABLE and _port_key not in NETMIKO_SESSIONS:
        try:
            nm = ConnectHandler(
                device_type="cisco_ios",
                host=WINDOWS_IP,
                port=port,
                username=GNS3_USERNAME,
                password=GNS3_PASSWORD,
                timeout=15,
                banner_timeout=5,   # fast-fail if port speaks Telnet (0xff IAC)
            )
            NETMIKO_SESSIONS[_port_key] = nm
            raw['_netmiko_connected'] = True
            logs.append("[COLLECT] Netmiko SSH session established.")
        except Exception as e:
            err_str = str(e)
            if '0xff' in err_str or 'banner' in err_str.lower():
                _TELNET_ONLY_PORTS.add(_port_key)   # cache: skip SSH next time
                logs.append(f"[COLLECT] Port {port} speaks Telnet — SSH skipped in future.")
            else:
                logs.append(f"[COLLECT] Netmiko SSH unavailable: {err_str[:60]}")

    logs.append(f"[COLLECT] Done. Keys: {list(raw.keys())}")
    return raw


def _safe_to_dict_collect(obj) -> dict:
    """Recursively convert Genie objects to plain dicts."""
    if hasattr(obj, 'to_dict'):
        return obj.to_dict()
    if hasattr(obj, '__dict__'):
        return {k: _safe_to_dict_collect(v) for k, v in obj.__dict__.items() if not k.startswith('_')}
    if isinstance(obj, dict):
        return {k: _safe_to_dict_collect(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_safe_to_dict_collect(i) for i in obj]
    return obj


def _mock_twin(cmds):
    """
    Offline/unavailable fallback - returns an EMPTY but structurally valid
    raw_twin so all downstream code paths work without crashing.
    NO hardcoded IPs, hostnames, protocol state, or topology data.
    Real data only comes from live MCP -> Netmiko SSH -> PyATS+Genie collection.
    """
    return {
        "interface":             {"info": {}},
        "routing":               {"vrf": {"default": {"address_family": {"ipv4": {"routes": {}}}}}},
        "ospf":                  {},
        "bgp":                   {},
        "bgp_summary":           {},
        "bgp_neighbors_detail":  {},
        "cdp_neighbors":         {"index": {}},
        "lldp_neighbors":        {"interfaces": {}},
        "acl":                   {"acls": {}},
        "vlan":                  {"vlans": {}},
        "platform":              {},
        "ospf_neighbors_detail": {},
        "ospf_neighbors_raw_cli": "",
        "ospf_database":         {},
        "ip_interface_brief":    {},
        "running_config":        "",
        "_offline_mode":         True,
        "_collection_note":      (
            "Device unreachable or pyATS/Genie unavailable. "
            "All fields empty. Run /discover with live device for real data. "
            "Connect via MCP -> Netmiko SSH -> PyATS+Genie to populate."
        ),
    }


# ══════════════════════════════════════════════════════════════════════════════
# INVENTORY EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════
def extract_inventory(raw, logs):
    logs.append("[INV] Extracting inventory...")
    inv = {
        "interfaces": [], "ip_addresses": [],
        "protocols": {"ospf": {}, "bgp": {}, "static": [], "eigrp": {}, "rip": {}},
        "acl": [], "route_maps": [],
        "cdp_neighbors": [], "lldp_neighbors": [],
    }

    # INTERFACES
    iface_data = raw.get("interface", {}).get("info", {})
    for name, d in iface_data.items():
        ips = list(d.get("ipv4", {}).keys())
        inv["interfaces"].append({
            "name": name, "oper_status": d.get("oper_status", "unknown"),
            "admin_status": d.get("enabled", True), "ip_addresses": ips,
            "description": d.get("description", ""), "mtu": d.get("mtu", ""),
            "bandwidth": d.get("bandwidth", ""), "speed": d.get("port_speed", ""),
            "mac": d.get("phys_address", ""),
            "encapsulation": d.get("encapsulation", {}).get("encapsulation", ""),
            "in_errors": d.get("counters", {}).get("in_errors", 0),
            "out_errors": d.get("counters", {}).get("out_errors", 0),
            "in_pkts": d.get("counters", {}).get("in_pkts", 0),
            "out_pkts": d.get("counters", {}).get("out_pkts", 0),
        })
        for ip_cidr in ips:
            inv["ip_addresses"].append({
                "interface": name, "ip_cidr": ip_cidr,
                "ip": ip_cidr.split("/")[0],
                "prefix": ip_cidr.split("/")[1] if "/" in ip_cidr else "32",
                "type": "loopback" if "loopback" in name.lower()
                        else "subinterface" if "." in name else "physical",
                "status": d.get("oper_status", "unknown"),
            })

    routes = (raw.get("routing", {}).get("vrf", {}).get("default", {})
                 .get("address_family", {}).get("ipv4", {}).get("routes", {}))

    # OSPF
    ospf_rx, ospf_adv, ospf_nbrs = [], [], []

    for pfx, r in routes.items():
        proto = r.get("source_protocol", "")
        nh_list = r.get("next_hop", {}).get("next_hop_list", {})
        nh = list(nh_list.values())[0].get("next_hop", "") if nh_list else ""
        if proto == "ospf":
            ospf_rx.append({"prefix": pfx, "next_hop": nh,
                            "metric": r.get("metric", ""), "age": r.get("last_updated", "")})
        elif proto == "connected":
            ospf_adv.append(pfx)
        elif proto == "static":
            inv["protocols"]["static"].append({"prefix": pfx, "next_hop": nh})

    # Walk OSPF data — use multi-source extractor for reliability
    ospf_nbrs_all = _extract_ospf_neighbors_all_sources(raw)
    for nbr_id, nbr_d in ospf_nbrs_all.items():
        ospf_nbrs.append({
            "neighbor_id": nbr_id,
            "state":       nbr_d.get("state", ""),
            "interface":   nbr_d.get("interface", ""),
            "area":        nbr_d.get("area", ""),
            "address":     nbr_d.get("address", ""),
            "dead_timer":  nbr_d.get("dead_timer", ""),
            "uptime":      nbr_d.get("uptime", ""),
            "priority":    nbr_d.get("priority", ""),
            "role":        nbr_d.get("role", ""),
        })

    # De-dup OSPF neighbors
    seen_nbr = set()
    ospf_nbrs_dedup = []
    for n in ospf_nbrs:
        key = f"{n['neighbor_id']}|{n.get('interface','')}"
        if key not in seen_nbr:
            seen_nbr.add(key)
            ospf_nbrs_dedup.append(n)

    inv["protocols"]["ospf"] = {
        "enabled": len(ospf_nbrs_dedup) > 0 or len(ospf_rx) > 0,
        "neighbors": ospf_nbrs_dedup,
        "routes_received": ospf_rx,
        "routes_advertised": ospf_adv,
        "route_count_rx": len(ospf_rx),
    }

    # BGP — robust multi-shape parsing
    bgp_nbrs, bgp_rx, bgp_adv = [], [], []

    # Shape 1: Genie bgp learn (instance → vrf → neighbor)
    bgp_learn = raw.get("bgp", {})
    for inst_name, inst in bgp_learn.get("instance", {}).items():
        for vrf_n, vrf_d in inst.get("vrf", {}).items():
            for nbr_ip, nbr_d in vrf_d.get("neighbor", {}).items():
                bgp_nbrs.append({
                    "neighbor": nbr_ip,
                    "vrf": vrf_n,
                    "remote_as": nbr_d.get("remote_as", nbr_d.get("bgp_neighbor_counters", {}).get("remote_as", "")),
                    "state": nbr_d.get("session_state", nbr_d.get("bgp_state", "")),
                    "prefixes_received": nbr_d.get("address_family", {}).get("ipv4 unicast", {}).get("accepted_prefix_count", ""),
                    "prefixes_sent": nbr_d.get("address_family", {}).get("ipv4 unicast", {}).get("sent_prefix_count", ""),
                    "uptime": nbr_d.get("up_time", nbr_d.get("bgp_session_transport", {}).get("connection", {}).get("last_reset", "")),
                    "description": nbr_d.get("description", ""),
                    "hold_time": nbr_d.get("hold_time", ""),
                    "keepalive": nbr_d.get("keepalive_interval", ""),
                })
            # BGP advertised prefixes
            for af_name, af_d in vrf_d.get("address_family", {}).items():
                for pfx in af_d.get("prefixes", {}).keys():
                    bgp_adv.append(pfx)

    # Shape 2: bgp_summary parsed output (vrf → neighbor)
    bgp_sum = raw.get("bgp_summary", {})
    for vrf_name, vrf_d in bgp_sum.get("vrf", {}).items():
        for nbr_ip, nbr_d in vrf_d.get("neighbor", {}).items():
            if not any(b["neighbor"] == nbr_ip for b in bgp_nbrs):
                bgp_nbrs.append({
                    "neighbor": nbr_ip, "vrf": vrf_name,
                    "remote_as": nbr_d.get("remote_as", ""),
                    "state": nbr_d.get("session_state", nbr_d.get("state_pfxrcd", "")),
                    "prefixes_received": nbr_d.get("prefixes_received", nbr_d.get("msg_rcvd", "")),
                    "prefixes_sent": nbr_d.get("msg_sent", ""),
                    "uptime": nbr_d.get("up_down", ""),
                    "description": "", "hold_time": "", "keepalive": "",
                })

    # Shape 3: bgp_neighbors_detail parsed
    bgp_nbr_detail = raw.get("bgp_neighbors_detail", {})
    if isinstance(bgp_nbr_detail, dict):
        for vrf_n, vrf_d in bgp_nbr_detail.get("vrf", {}).items():
            for nbr_ip, nbr_d in vrf_d.get("neighbor", {}).items():
                if not any(b["neighbor"] == nbr_ip for b in bgp_nbrs):
                    bgp_nbrs.append({
                        "neighbor": nbr_ip, "vrf": vrf_n,
                        "remote_as": nbr_d.get("remote_as", ""),
                        "state": nbr_d.get("session_state", ""),
                        "prefixes_received": nbr_d.get("address_family", {}).get("ipv4 unicast", {}).get("accepted_prefix_count", ""),
                        "prefixes_sent": "",
                        "uptime": nbr_d.get("up_time", ""),
                        "description": nbr_d.get("description", ""),
                        "hold_time": nbr_d.get("hold_time", ""),
                        "keepalive": nbr_d.get("keepalive_interval", ""),
                    })

    # BGP routes from routing table
    for pfx, r in routes.items():
        if r.get("source_protocol") == "bgp":
            nh_list = r.get("next_hop", {}).get("next_hop_list", {})
            nh = list(nh_list.values())[0].get("next_hop", "") if nh_list else ""
            bgp_rx.append({"prefix": pfx, "next_hop": nh})

    inv["protocols"]["bgp"] = {
        "enabled": len(bgp_nbrs) > 0,
        "neighbors": bgp_nbrs,
        "routes_received": bgp_rx,
        "routes_advertised": list(dict.fromkeys(bgp_adv)),
        "neighbor_count": len(bgp_nbrs),
    }

    # ACL — Genie acl learn
    acl_learn = raw.get("acl", {})
    for acl_name, acl_d in acl_learn.get("acls", {}).items():
        aces = []
        for seq, ace in sorted(acl_d.get("aces", {}).items(),
                                key=lambda x: int(x[0]) if str(x[0]).isdigit() else 0):
            aces.append({
                "seq": seq,
                "action": ace.get("actions", {}).get("forwarding", ""),
                "proto": ace.get("matches", {}).get("l3", {}).get("ipv4", {}).get("protocol", ""),
                "src": ace.get("matches", {}).get("l3", {}).get("ipv4", {}).get("source_network", {}).get("source_network", "any"),
                "dst": ace.get("matches", {}).get("l3", {}).get("ipv4", {}).get("destination_network", {}).get("destination_network", "any"),
                "hits": ace.get("statistics", {}).get("matched_packets", 0),
            })
        inv["acl"].append({
            "name": acl_name, "type": acl_d.get("type", ""),
            "aces": aces, "applied_interfaces": _find_acl_ifaces(acl_name, iface_data),
        })

    # ACL fallback from running-config
    if not inv["acl"]:
        rc = raw.get("running_config", "")
        if isinstance(rc, str):
            current_acl = None
            for line in rc.split("\n"):
                m = re.match(r'ip access-list\s+(standard|extended)\s+(\S+)', line)
                if m:
                    current_acl = {"name": m.group(2), "type": m.group(1), "aces": [], "applied_interfaces": []}
                    inv["acl"].append(current_acl)
                elif current_acl and line.strip() and not line.startswith("!"):
                    current_acl["aces"].append({"seq": "", "action": "", "text": line.strip()})

    # ROUTE-MAPS
    rm_parsed = raw.get("route_maps", {})
    if isinstance(rm_parsed, dict) and rm_parsed:
        for rm_name, rm_d in rm_parsed.items():
            seqs = []
            for seq_num, seq_d in rm_d.items():
                if isinstance(seq_d, dict):
                    seqs.append({"seq": seq_num, "action": seq_d.get("action", ""),
                                 "match": seq_d.get("match", {}), "set": seq_d.get("set", {})})
            inv["route_maps"].append({"name": rm_name, "sequences": seqs})

    if not inv["route_maps"]:
        rc = raw.get("running_config", "")
        if isinstance(rc, str):
            cur_rm = None
            for line in rc.split("\n"):
                m = re.match(r'route-map\s+(\S+)\s+(permit|deny)\s+(\d+)', line)
                if m:
                    rm_name = m.group(1)
                    existing = next((r for r in inv["route_maps"] if r["name"] == rm_name), None)
                    seq_entry = {"seq": m.group(3), "action": m.group(2), "body": "", "match": {}, "set": {}}
                    if existing:
                        existing["sequences"].append(seq_entry)
                        cur_rm = seq_entry
                    else:
                        new_rm = {"name": rm_name, "sequences": [seq_entry]}
                        inv["route_maps"].append(new_rm)
                        cur_rm = seq_entry
                elif cur_rm and line.strip().startswith("match "):
                    cur_rm["body"] = cur_rm.get("body", "") + line.strip() + "\n"
                elif cur_rm and line.strip().startswith("set "):
                    cur_rm["body"] = cur_rm.get("body", "") + line.strip() + "\n"

    # CDP (preserves ALL entries including multiple links per device)
    cdp = raw.get("cdp_neighbors", {})
    if isinstance(cdp, dict):
        for idx, entry in cdp.get("index", {}).items():
            ip_info = entry.get("management_addresses", {}) or entry.get("entry_addresses", {})
            ip_str = list(ip_info.keys())[0] if ip_info else ""
            inv["cdp_neighbors"].append({
                "device_id": entry.get("device_id", ""),
                "local_interface": entry.get("local_interface", ""),
                "remote_interface": entry.get("port_id", ""),
                "platform": entry.get("platform", ""),
                "capabilities": entry.get("capabilities", ""),
                "ip": ip_str,
                "software": (entry.get("software_version", "") or "")[:80],
            })

    # LLDP
    lldp = raw.get("lldp_neighbors", {})
    if isinstance(lldp, dict):
        for iface_name, iface_d in lldp.get("interfaces", {}).items():
            for port_id, port_d in iface_d.get("port_id", {}).items():
                nbrs = port_d.get("neighbors", {})
                for chassis_id, nbr_info in nbrs.items():
                    inv["lldp_neighbors"].append({
                        "local_interface": iface_name,
                        "remote_interface": port_id,
                        "chassis_id": chassis_id,
                        "system_name": nbr_info.get("system_name", ""),
                        "system_description": (nbr_info.get("system_description", "") or "")[:80],
                    })

    logs.append(f"[INV] Done: {len(inv['interfaces'])} ifaces, {len(inv['ip_addresses'])} IPs, "
                f"{len(inv['cdp_neighbors'])} CDP, {len(inv['acl'])} ACLs, {len(inv['route_maps'])} RMs, "
                f"BGP nbrs: {len(inv['protocols']['bgp']['neighbors'])}, "
                f"OSPF nbrs: {len(inv['protocols']['ospf']['neighbors'])}")
    return inv


def _extract_ospf_neighbors_all_sources(raw: dict) -> dict:
    """
    Extract OSPF neighbors from ALL available raw sources, in priority order:
      1. raw['ospf_neighbors_raw_cli'] — raw text of 'show ip ospf neighbor' (most reliable)
      2. raw['ospf_neighbors_detail']  — Genie parsed (multiple schema variants handled)
      3. raw['ospf']                   — Genie learn ospf (instance→vrf→area→interface→neighbor)
      4. raw['running_config']         — last resort: config-inferred

    Returns dict: { neighbor_id: {"state": ..., "interface": ..., "address": ...,
                                   "priority": ..., "dead_timer": ..., "role": ...} }
    NEVER returns empty if neighbors exist — handles all IOS/IOS-XE/GNS3 Genie schema variants.
    """
    nbrs = {}

    # ── Source 0: Raw CLI text — most reliable, bypasses ALL Genie schema issues ──
    # 'show ip ospf neighbor' output:
    # Neighbor ID     Pri   State           Dead Time   Address         Interface
    # 9.9.0.3           1   FULL/DR         00:00:36    9.9.23.3        FastEthernet0/0
    ospf_raw_cli = raw.get("ospf_neighbors_raw_cli", "")
    if isinstance(ospf_raw_cli, str) and ospf_raw_cli.strip():
        for line in ospf_raw_cli.splitlines():
            # Match the standard 'show ip ospf neighbor' table row
            m = re.match(
                r'\s*(\d+\.\d+\.\d+\.\d+)\s+'   # Neighbor ID
                r'(\d+)\s+'                       # Priority
                r'([\w/]+)\s+'                    # State (e.g. FULL/DR, FULL/BDR, 2WAY/DROTHER)
                r'(\S+)\s+'                       # Dead Time
                r'(\d+\.\d+\.\d+\.\d+)\s+'       # Address
                r'(\S+)',                          # Interface
                line
            )
            if m:
                nbr_id, pri, state, dead, addr, iface = m.groups()
                nbrs[nbr_id] = {
                    "state":      state,           # e.g. "FULL/DR"
                    "interface":  iface,
                    "address":    addr,
                    "priority":   pri,
                    "dead_timer": dead,
                    "role":       state.split("/")[1] if "/" in state else "",
                    "uptime":     "",
                    "source":     "raw_cli",
                }
        if nbrs:
            return nbrs  # Raw CLI is authoritative — return immediately

    # ── Source 1: Genie parsed 'show ip ospf neighbor detail' ─────────────
    # Classic IOS shape (no vrf wrapper):
    #   { "interfaces": { "FastEthernet0/0": { "neighbors": { "9.9.0.3": {...} } } } }
    # IOS-XE shape (vrf wrapper):
    #   { "vrf": { "default": { "interfaces": { "Fa0/0": { "neighbors": { ... } } } } } }
    ospf_nbr_detail = raw.get("ospf_neighbors_detail", {})
    if isinstance(ospf_nbr_detail, dict) and not nbrs:
        # Try IOS-XE shape first (vrf wrapper)
        for vrf_n, vrf_d in ospf_nbr_detail.get("vrf", {}).items():
            for iface_name, iface_d in vrf_d.get("interfaces", {}).items():
                for nbr_id, nbr_d in iface_d.get("neighbors", {}).items():
                    nbrs[nbr_id] = {
                        "state":      nbr_d.get("state", "UNKNOWN"),
                        "interface":  iface_name,
                        "address":    nbr_d.get("address", ""),
                        "priority":   str(nbr_d.get("priority", "")),
                        "dead_timer": nbr_d.get("dead_time", ""),
                        "role":       nbr_d.get("role", ""),
                        "uptime":     nbr_d.get("up_time", ""),
                        "source":     "genie_detail_iosxe",
                    }

        # Try classic IOS shape (no vrf wrapper, interfaces at top level)
        if not nbrs:
            for iface_name, iface_d in ospf_nbr_detail.get("interfaces", {}).items():
                for nbr_id, nbr_d in iface_d.get("neighbors", {}).items():
                    nbrs[nbr_id] = {
                        "state":      nbr_d.get("state", "UNKNOWN"),
                        "interface":  iface_name,
                        "address":    nbr_d.get("address", ""),
                        "priority":   str(nbr_d.get("priority", "")),
                        "dead_timer": nbr_d.get("dead_time", ""),
                        "role":       nbr_d.get("role", ""),
                        "uptime":     nbr_d.get("up_time", ""),
                        "source":     "genie_detail_ios",
                    }

        # Brute-force: recursively find any dict with "state" + "address" keys (handles unknown shapes)
        if not nbrs:
            def _find_nbr_dicts(d, iface_hint="", depth=0):
                if depth > 10: return
                if isinstance(d, dict):
                    # Check if this dict looks like a neighbor entry
                    if ("state" in d and
                        any(re.match(r'\d+\.\d+\.\d+\.\d+', str(k)) for k in [iface_hint])):
                        pass
                    # Recurse
                    for k, v in d.items():
                        if isinstance(v, dict):
                            # If k looks like an IP → neighbor ID
                            if re.match(r'\d+\.\d+\.\d+\.\d+', str(k)) and "state" in v:
                                nbrs[k] = {
                                    "state":      v.get("state", "UNKNOWN"),
                                    "interface":  v.get("interface", iface_hint),
                                    "address":    v.get("address", ""),
                                    "priority":   str(v.get("priority", "")),
                                    "dead_timer": v.get("dead_time", v.get("dead_timer", "")),
                                    "role":       v.get("role", ""),
                                    "uptime":     v.get("up_time", ""),
                                    "source":     "genie_detail_brute",
                                }
                            else:
                                _find_nbr_dicts(v, iface_hint=k, depth=depth+1)
            _find_nbr_dicts(ospf_nbr_detail)

    # ── Source 2: Genie ospf learn (instance→vrf→area→interface→neighbor) ─
    # Shape: { "1": { "vrf": { "default": { "area": { "0": {
    #           "interface": { "Fa0/0": { "neighbor": { "9.9.0.3": {
    #             "state": "FULL", "address": "9.9.23.3" } } } } } } } } }
    if not nbrs:
        for inst_name, inst in raw.get("ospf", {}).items():
            if not isinstance(inst, dict): continue
            for vrf_n, vrf_d in inst.get("vrf", {}).items():
                for area_id, area_d in vrf_d.get("area", {}).items():
                    for iface_name, iface_d in area_d.get("interface", {}).items():
                        for nbr_id, nbr_d in iface_d.get("neighbor", {}).items():
                            if nbr_id not in nbrs:
                                nbrs[nbr_id] = {
                                    "state":     nbr_d.get("state", "UNKNOWN"),
                                    "interface": iface_name,
                                    "address":   nbr_d.get("address", ""),
                                    "priority":  str(nbr_d.get("priority", "")),
                                    "dead_timer":"",
                                    "role":      "",
                                    "uptime":    "",
                                    "source":    "ospf_learn",
                                }

    # ── Source 3: running-config inference (last resort — marks as UNKNOWN) ─
    if not nbrs:
        rc = raw.get("running_config", "")
        if isinstance(rc, str):
            ospf_ifaces = re.findall(r'interface\s+(\S+).*?ip ospf\s+\d+\s+area\s+(\d+)',
                                     rc, re.S | re.I)
            for iface_name, area in ospf_ifaces[:8]:
                key = f"config-inferred-{iface_name}"
                nbrs[key] = {
                    "state":     "UNKNOWN (config-only — live neighbor data unavailable)",
                    "interface": iface_name,
                    "address":   "",
                    "priority":  "",
                    "dead_timer":"",
                    "role":      "",
                    "uptime":    "",
                    "source":    "running_config_inferred",
                }

    return nbrs


def _format_ospf_neighbors_for_prompt(nbrs: dict) -> str:
    """
    Format OSPF neighbor dict into a human-readable string for LLM prompts.
    Explicitly labels FULL/DR, FULL/BDR, 2WAY states as ACTIVE to prevent misinterpretation.
    """
    if not nbrs:
        return "NONE — no active OSPF neighbors detected in any data source (raw CLI + Genie)"

    lines = []
    for nbr_id, d in nbrs.items():
        state = d.get("state", "UNKNOWN")
        # Tag the state clearly for the LLM
        is_active = bool(re.search(r'FULL|2WAY', state.upper()))
        active_tag = "⚠ ACTIVE ADJACENCY" if is_active else "inactive"
        lines.append(
            f"  Neighbor {nbr_id}: state={state} [{active_tag}] "
            f"iface={d['interface']} addr={d['address']} "
            f"priority={d['priority']} dead_timer={d['dead_timer']} "
            f"source={d['source']}"
        )

    active_count = sum(1 for d in nbrs.values()
                       if re.search(r'FULL|2WAY', str(d.get("state","")).upper()))
    header = (f"⚠ WARNING: {active_count} ACTIVE NEIGHBOR(S) IN FULL/2WAY STATE — "
              f"REMOVING OSPF PROCESS WILL CAUSE IMMEDIATE OUTAGE\n"
              if active_count > 0
              else f"{len(nbrs)} NEIGHBOR(S) (none in FULL/2WAY state):\n")
    return header + "\n".join(lines)


def _find_acl_ifaces(acl_name, iface_data):
    applied = []
    for iname, d in iface_data.items():
        for direction in ["in", "out"]:
            for atype in ["ipv4", "ipv6"]:
                ref = d.get("acl", {}).get(direction, {}).get(atype, {}).get("acl_name", "")
                if ref == acl_name:
                    applied.append(f"{iname} ({direction})")
    return applied


# ══════════════════════════════════════════════════════════════════════════════
# PHYSICAL + LOGICAL TOPOLOGY (multi-link aware)
# ══════════════════════════════════════════════════════════════════════════════
def build_topology(inv, raw, local_id, logs):
    """
    Multi-link aware topology builder.
    - All CDP entries become separate physical edges (even multiple links to same device)
    - LLDP edges complement CDP
    - OSPF logical topology from database (not just direct adjacencies)
    - OSPF logical topology uses interface-level adjacencies for proper multi-link display
    """
    topo_nodes = {}
    topo_edges = []   # list — NOT deduplicated by node pair, to show multi-link

    topo_nodes[local_id] = {
        "id": local_id, "label": local_id, "type": "local",
        "platform": "Cisco IOS (local)", "interfaces": [],
    }

    # CDP — every entry is a separate edge (multiple links to same device preserved)
    for nbr in inv.get("cdp_neighbors", []):
        dev_id = (nbr.get("device_id", "") or "").split(".")[0]
        if not dev_id:
            continue
        local_if = nbr.get("local_interface", "")
        rem_if   = nbr.get("remote_interface", "")
        platform = nbr.get("platform", "")
        ip_str   = nbr.get("ip", "")

        if dev_id not in topo_nodes:
            topo_nodes[dev_id] = {"id": dev_id, "label": dev_id, "type": "cdp",
                                  "platform": platform, "ip": ip_str}
        # Always add edge — multiple links between same two devices will appear as multiple edges
        topo_edges.append({
            "source": local_id, "target": dev_id,
            "local_if": local_if, "remote_if": rem_if,
            "link_type": "physical", "source_proto": "CDP",
        })

    # LLDP — add only if interface not already covered by CDP
    cdp_local_ifs = {e["local_if"] for e in topo_edges if e["source_proto"] == "CDP"}
    for nbr in inv.get("lldp_neighbors", []):
        local_if = nbr.get("local_interface", "")
        if local_if in cdp_local_ifs:
            continue  # CDP already has this physical link
        dev_id = nbr.get("system_name", "") or nbr.get("chassis_id", "") or f"lldp-dev"
        if dev_id not in topo_nodes:
            topo_nodes[dev_id] = {"id": dev_id, "label": dev_id, "type": "lldp", "platform": ""}
        topo_edges.append({
            "source": local_id, "target": dev_id,
            "local_if": local_if, "remote_if": nbr.get("remote_interface", ""),
            "link_type": "physical", "source_proto": "LLDP",
        })

    # OSPF logical adjacencies — one edge per adjacency (interface-level)
    ospf_nbrs = inv.get("protocols", {}).get("ospf", {}).get("neighbors", [])
    physical_targets = {e["target"] for e in topo_edges}

    for nbr in ospf_nbrs:
        nbr_id = nbr.get("neighbor_id", "")
        if not nbr_id:
            continue
        local_if = nbr.get("interface", "")
        state    = nbr.get("state", "")
        area     = nbr.get("area", "")

        if nbr_id not in topo_nodes:
            topo_nodes[nbr_id] = {"id": nbr_id, "label": nbr_id,
                                  "type": "ospf", "platform": ""}

        # Only add logical edge if this interface isn't already showing physical link to same node
        phys_exists = any(e["source"] == local_id and e["target"] == nbr_id
                          and e["local_if"] == local_if and e["link_type"] == "physical"
                          for e in topo_edges)
        if not phys_exists:
            topo_edges.append({
                "source": local_id, "target": nbr_id,
                "local_if": local_if, "remote_if": "",
                "link_type": "logical_l3", "source_proto": "OSPF",
                "state": state, "area": area,
            })

    # OSPF database logical topology (inferred from routing — other routers visible via OSPF DB)
    ospf_db = raw.get("ospf_database", {})
    if isinstance(ospf_db, dict):
        for k, v in ospf_db.items():
            if isinstance(v, dict) and "router_id" in v:
                rid = v["router_id"]
                if rid and rid != local_id and rid not in topo_nodes:
                    topo_nodes[rid] = {"id": rid, "label": rid, "type": "ospf_db", "platform": ""}
                    topo_edges.append({
                        "source": local_id, "target": rid,
                        "local_if": "", "remote_if": "",
                        "link_type": "logical_ospf_db", "source_proto": "OSPF-DB",
                        "state": "learned", "area": "",
                    })

    logs.append(f"[TOPO] Nodes: {len(topo_nodes)}, Edges: {len(topo_edges)} (multi-link preserved)")
    return {"nodes": list(topo_nodes.values()), "edges": topo_edges, "local_node": local_id}


# ══════════════════════════════════════════════════════════════════════════════
# IGRAPH CENTRALITY
# ══════════════════════════════════════════════════════════════════════════════
def stage_igraph_analysis(raw, logs):
    logs.append("[STAGE 2] igraph Centrality Analysis starting...")
    if not IGRAPH_AVAILABLE:
        logs.append("[STAGE 2] igraph unavailable — building minimal topology from raw data.")
        return _build_minimal_topology_without_igraph(raw, logs)

    iface_data = raw.get("interface", {}).get("info", {})
    local_node = None
    loopback_ips, iface_ips = [], []

    for iface, details in iface_data.items():
        if details.get("oper_status") != "up":
            continue
        for ip_block in details.get("ipv4", {}).keys():
            ip, plen = (ip_block.split("/") + ["32"])[:2]
            if "loopback" in iface.lower() or plen == "32":
                loopback_ips.append(ip)
            else:
                iface_ips.append(ip)

    local_node = sorted(loopback_ips)[0] if loopback_ips else (sorted(iface_ips)[0] if iface_ips else "self")
    logs.append(f"[STAGE 2] Local node: {local_node}")

    nodes = set([local_node])
    edge_set = {}  # (a,b) sorted → weight

    routes = (raw.get("routing", {}).get("vrf", {}).get("default", {})
                 .get("address_family", {}).get("ipv4", {}).get("routes", {}))

    for pfx, rinfo in routes.items():
        proto = rinfo.get("source_protocol", "")
        w = {"ospf": 1.0, "connected": 0.5, "static": 2.0, "local": 0.1, "bgp": 1.5}.get(proto, 1.5)
        if proto in ("connected", "local"):
            sn = pfx.split("/")[0]
            nodes.add(sn)
            edge_set.setdefault(tuple(sorted([local_node, sn])), w)
        else:
            for _, nh in rinfo.get("next_hop", {}).get("next_hop_list", {}).items():
                nh_ip = nh.get("next_hop", "").strip()
                if nh_ip:
                    nodes.add(nh_ip)
                    edge_set.setdefault(tuple(sorted([local_node, nh_ip])), w)

    # OSPF neighbor edges (authoritative)
    def _get_ospf_nbrs(ospf_d, depth=0):
        nbrs = {}
        if depth > 8: return nbrs
        for k, v in ospf_d.items():
            if isinstance(v, dict):
                if "state" in v:
                    nbrs[k] = v
                else:
                    nbrs.update(_get_ospf_nbrs(v, depth + 1))
        return nbrs

    for nbr_id, nbr_d in _get_ospf_nbrs(raw.get("ospf", {})).items():
        if re.match(r'\d+\.\d+\.\d+\.\d+', str(nbr_id)):
            nodes.add(nbr_id)
            edge_set.setdefault(tuple(sorted([local_node, nbr_id])), 1.0)

    if len(nodes) < 2 or not edge_set:
        logs.append("[STAGE 2] Sparse topology.")
        topo = {"nodes": [{"id": local_node, "betweenness": 1.0, "degree": 0,
                            "closeness": 0.0, "pagerank": 1.0, "criticality": 1.0}],
                "edges": [], "graph_stats": {"node_count": 1, "edge_count": 0,
                                              "density": 0.0, "diameter": 0, "avg_degree": 0}}
        return topo, [topo["nodes"][0]]

    node_list = list(nodes)
    node_idx = {n: i for i, n in enumerate(node_list)}
    g = ig.Graph(directed=False)
    g.add_vertices(len(node_list))
    g.vs["name"] = node_list

    edge_tuples, edge_weights = [], []
    for (s, t), w in edge_set.items():
        if s in node_idx and t in node_idx:
            edge_tuples.append((node_idx[s], node_idx[t]))
            edge_weights.append(w)

    g.add_edges(edge_tuples)
    if edge_weights:
        g.es["weight"] = edge_weights

    w_arg = edge_weights or None
    betweenness = g.betweenness(weights=w_arg)
    degree = g.degree()
    closeness = g.closeness(weights=w_arg)
    pagerank = g.pagerank(weights=w_arg)

    max_bw = max(betweenness) if max(betweenness) > 0 else 1
    norm_bw = [b / max_bw for b in betweenness]
    max_deg = max(degree) if max(degree) > 0 else 1
    max_pr = max(pagerank) if max(pagerank) > 0 else 1

    criticality = [0.5 * norm_bw[i] + 0.3 * (pagerank[i] / max_pr) + 0.2 * (degree[i] / max_deg)
                   for i in range(len(node_list))]

    topology = {
        "nodes": [{"id": node_list[i], "betweenness": round(norm_bw[i], 4),
                   "degree": degree[i], "closeness": round(closeness[i] or 0, 4),
                   "pagerank": round(pagerank[i], 4), "criticality": round(criticality[i], 4)}
                  for i in range(len(node_list))],
        "edges": [{"source": node_list[e[0]], "target": node_list[e[1]],
                   "weight": edge_weights[j] if j < len(edge_weights) else 1.0}
                  for j, e in enumerate(edge_tuples)],
        "graph_stats": {"node_count": len(node_list), "edge_count": len(edge_tuples),
                        "density": round(g.density(), 4),
                        "diameter": g.diameter() if g.is_connected() else -1,
                        "avg_degree": round(sum(degree) / len(degree), 2) if degree else 0},
    }

    sorted_nodes = sorted(topology["nodes"], key=lambda x: x["criticality"], reverse=True)
    critical_nodes = sorted_nodes[:max(1, len(sorted_nodes) // 3)]
    logs.append(f"[STAGE 2] Graph: {len(node_list)} nodes, {len(edge_tuples)} edges")
    return topology, critical_nodes


def _build_minimal_topology_without_igraph(raw: dict, logs: list):
    """
    Fallback when igraph is not installed.
    Builds REAL topology from actual Genie-collected data (interface, routing, OSPF, CDP).
    Returns same structure as stage_igraph_analysis() - NO hardcoded IPs or topology.
    """
    nodes = {}
    edges = []

    iface_data = raw.get("interface", {}).get("info", {})
    routes = (raw.get("routing", {}).get("vrf", {}).get("default", {})
                 .get("address_family", {}).get("ipv4", {}).get("routes", {}))

    # Determine local node from Loopback0 or first up interface IP
    local_node = None
    for iname, det in iface_data.items():
        if det.get("oper_status") == "up":
            for ip_b in det.get("ipv4", {}).keys():
                ip, plen = (ip_b.split("/") + ["32"])[:2]
                if "loopback" in iname.lower() or plen == "32":
                    if not local_node or iname.lower() == "loopback0":
                        local_node = ip
    if not local_node:
        for iname, det in iface_data.items():
            for ip_b in det.get("ipv4", {}).keys():
                local_node = ip_b.split("/")[0]
                break
            if local_node:
                break

    if not local_node:
        logs.append("[STAGE 2] No interfaces found in raw data — offline/empty device.")
        empty_topo = {"nodes": [], "edges": [], "graph_stats": {"node_count": 0, "edge_count": 0, "density": 0.0, "diameter": 0, "avg_degree": 0}}
        return empty_topo, []

    logs.append(f"[STAGE 2] Local node identified: {local_node}")
    nodes[local_node] = {"id": local_node, "betweenness": 1.0, "degree": 0, "closeness": 1.0, "pagerank": 1.0, "criticality": 1.0}

    # Add neighbors from routing table next-hops
    for pfx, r in routes.items():
        proto = r.get("source_protocol", "")
        w = {"ospf": 1.0, "bgp": 1.5, "connected": 0.5, "static": 2.0}.get(proto, 1.5)
        for _, nh in r.get("next_hop", {}).get("next_hop_list", {}).items():
            nh_ip = nh.get("next_hop", "").strip()
            if nh_ip and nh_ip != local_node:
                if nh_ip not in nodes:
                    deg = len([e for e in edges if local_node in (e["source"], e["target"])])
                    nodes[nh_ip] = {"id": nh_ip, "betweenness": 0.3, "degree": 1, "closeness": 0.5, "pagerank": 0.2, "criticality": 0.3}
                edges.append({"source": local_node, "target": nh_ip, "weight": w})

    # Add OSPF neighbors as direct edges
    ospf_nbrs = _extract_ospf_neighbors_all_sources(raw)
    for nbr_id, nbr_d in ospf_nbrs.items():
        if nbr_id not in nodes:
            nodes[nbr_id] = {"id": nbr_id, "betweenness": 0.4, "degree": 1, "closeness": 0.5, "pagerank": 0.25, "criticality": 0.4}
        if not any(e["source"] == local_node and e["target"] == nbr_id for e in edges):
            edges.append({"source": local_node, "target": nbr_id, "weight": 1.0})

    # Add CDP neighbors
    for idx, entry in raw.get("cdp_neighbors", {}).get("index", {}).items():
        dev_id = (entry.get("device_id", "") or "").split(".")[0]
        ip_info = entry.get("management_addresses", {}) or entry.get("entry_addresses", {})
        nbr_ip = list(ip_info.keys())[0] if ip_info else dev_id
        if nbr_ip and nbr_ip not in nodes:
            nodes[nbr_ip] = {"id": nbr_ip, "betweenness": 0.2, "degree": 1, "closeness": 0.4, "pagerank": 0.15, "criticality": 0.25}
        if nbr_ip and not any(e["source"] == local_node and e["target"] == nbr_ip for e in edges):
            edges.append({"source": local_node, "target": nbr_ip, "weight": 0.8})

    # Degree update
    for n_id in nodes:
        deg = sum(1 for e in edges if e["source"] == n_id or e["target"] == n_id)
        nodes[n_id]["degree"] = deg

    node_list = list(nodes.values())
    max_deg = max((n["degree"] for n in node_list), default=1) or 1
    for n in node_list:
        n["criticality"] = round(0.6 * n["betweenness"] + 0.4 * (n["degree"] / max_deg), 4)

    sorted_nodes = sorted(node_list, key=lambda x: x["criticality"], reverse=True)
    critical = sorted_nodes[:max(1, len(sorted_nodes) // 3)]

    topo = {
        "nodes": node_list,
        "edges": edges,
        "graph_stats": {
            "node_count": len(node_list),
            "edge_count": len(edges),
            "density": round(len(edges) / max(1, len(node_list) * (len(node_list) - 1) / 2), 4),
            "diameter": -1,
            "avg_degree": round(sum(n["degree"] for n in node_list) / max(1, len(node_list)), 2),
        },
    }
    logs.append(f"[STAGE 2] Minimal topology: {len(node_list)} nodes, {len(edges)} edges (from real Genie data)")
    return topo, critical


# ══════════════════════════════════════════════════════════════════════════════
# STAGE 3: RECURSIVE HEALING (token-budgeted — single call for Claude)
# ══════════════════════════════════════════════════════════════════════════════
def stage_recursive_healing(intent, topology, critical_nodes, provider, logs,
                             max_iter=3, stage5_feedback=None):
    """
    Stage 3: Generate safe Cisco IOS CLI config for the given intent.

    stage5_feedback: list of NO-GO reason strings from Stage 5 (dynamic closed-loop).
    When provided, the LLM is told WHY the previous config was rejected and must
    produce a safer config that addresses those specific constraints.
    This is the Stage 5 → Stage 3 feedback path that makes the pipeline adaptive.
    """
    logs.append("[STAGE 3] Recursive Healing starting...")
    critical_ids = [n["id"] for n in critical_nodes]
    audit_trail  = []

    # Build feedback section from Stage 5 NO-GO reasons (dynamic learning)
    feedback_section = ""
    if stage5_feedback:
        logs.append(f"[STAGE 3] Stage 5 feedback: {len(stage5_feedback)} constraints to address.")
        feedback_section = (
            "\n\nPREVIOUS CONFIG REJECTED BY IMPACT ASSESSMENT — address these issues:\n" +
            "\n".join(f"• {c}" for c in stage5_feedback) +
            "\nGenerate a SAFER config that avoids ALL the above constraints."
        )

    if provider == "claude":
        # Single-pass for Claude (token budget: one call instead of 3)
        logs.append("[STAGE 3] Claude mode: single-pass heal (token-budget optimised)")
        system_prompt = (
            "You are a Cisco IOS SRE. Output ONLY syntactically correct Cisco IOS CLI "
            "commands, one per line. No prose, no markdown, no explanation."
        )
        prompt = (
            f"Intent: '{intent[:500]}'\n"
            f"Critical nodes (do NOT disrupt): {critical_ids[:5]}\n"
            f"Return safe Cisco IOS CLI commands to implement the intent. "
            f"Avoid shutdown/clear/reload on critical nodes. One command per line."
            f"{feedback_section}"
        )
        proposed = call_ai(prompt, provider, system=system_prompt)
        risk = _risk_score(proposed, critical_ids)
        accepted = risk < 0.5
        audit_trail.append({"iteration": 1, "proposed": proposed,
                             "risk_score": round(risk, 3), "accepted": accepted})
        logs.append(f"[STAGE 3] Claude single-pass: risk={risk:.3f} accepted={accepted}")
        return proposed, audit_trail

    # Ollama path: full 3-iteration loop with risk feedback
    # Seed context with Stage 5 feedback if present (Round 2 of decision loop)
    if stage5_feedback:
        current = (
            f"{intent}\n\nPREVIOUS IMPACT ASSESSMENT REJECTED THIS CONFIG.\n"
            "Generate a SAFER config that avoids:\n" +
            "\n".join(f"• {c}" for c in stage5_feedback)
        )
    else:
        current = intent

    for i in range(1, max_iter + 1):
        logs.append(f"[STAGE 3] Iteration {i}/{max_iter}")
        system_prompt = (
            "You are a Cisco IOS/IOS-XE SRE with 15 years of network operations experience. "
            "You produce only syntactically correct Cisco IOS CLI — no prose, no explanation, "
            "no markdown. Only raw CLI lines, one per line."
        )
        prompt = f"""Original intent: '{current}'
CRITICAL nodes that must NOT be disrupted: {critical_ids}
Constraint level for iteration {i}: {'VERY CONSERVATIVE — avoid all destructive commands.' if i > 1 else 'STANDARD — apply intent safely.'}

Return ONLY valid Cisco IOS CLI commands, one per line. No explanation."""
        proposed = call_ai(prompt, provider, system=system_prompt)
        risk = _risk_score(proposed, critical_ids)
        accepted = risk < 0.4
        audit_trail.append({"iteration": i, "proposed": proposed,
                             "risk_score": round(risk, 3), "accepted": accepted})
        logs.append(f"[STAGE 3] iter={i} risk={risk:.3f} accepted={accepted}")
        if accepted:
            return proposed, audit_trail
        current = f"{intent} [RISK={risk:.2f} — tighten on {critical_ids}]"

    best = min(audit_trail, key=lambda x: x["risk_score"])
    return best["proposed"], audit_trail


def _risk_score(cfg, critical_ids):
    score = 0.0
    cl = cfg.lower()
    for kw, w in [("no router", 0.3), ("shutdown", 0.25), ("no network", 0.2),
                  ("clear", 0.15), ("reload", 0.4), ("no ip route", 0.2)]:
        if kw in cl:
            score += w
    for line in cl.split("\n"):
        for cid in critical_ids:
            if cid in line and any(d in line for d in ["no ", "shutdown", "clear"]):
                score += 0.2
    return min(score, 1.0)


# ══════════════════════════════════════════════════════════════════════════════
# STAGE 4: VALIDATION
# ══════════════════════════════════════════════════════════════════════════════
def stage_variable_validation(healed_config, raw, topology, logs):
    logs.append("[STAGE 4] Variable Validation starting...")
    issues, warnings, passed = [], [], []

    device_iface_ips = set()
    iface_data = raw.get("interface", {}).get("info", {})
    for iface, details in iface_data.items():
        for ip_block in details.get("ipv4", {}).keys():
            device_iface_ips.add(ip_block.split("/")[0])

    device_routing_ips = set()
    routes = (raw.get("routing", {}).get("vrf", {}).get("default", {})
                 .get("address_family", {}).get("ipv4", {}).get("routes", {}))
    for pfx, rinfo in routes.items():
        device_routing_ips.add(pfx.split("/")[0])
        for _, nh in rinfo.get("next_hop", {}).get("next_hop_list", {}).items():
            nh_ip = nh.get("next_hop", "")
            if nh_ip:
                device_routing_ips.add(nh_ip)

    all_known = device_iface_ips | device_routing_ips
    logs.append(f"[STAGE 4] {len(device_iface_ips)} iface IPs, {len(device_routing_ips)} routing IPs")

    config_ips = list(dict.fromkeys(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', healed_config)))
    config_lines = healed_config.lower().split("\n")
    destructive = ("no ", "shutdown", "clear ", "reload")

    for ip in config_ips:
        destr = any(ip in l and any(d in l for d in destructive) for l in config_lines)
        if ip in device_iface_ips:
            if destr:
                issues.append(f"DANGER: {ip} is a live interface IP targeted by destructive command.")
            else:
                warnings.append(f"IP {ip} matches a live interface address — verify intent.")
        elif ip in device_routing_ips:
            passed.append(f"IP {ip} — known in routing table.")
        else:
            warnings.append(f"IP {ip} — NOT in device twin. Possible LLM hallucination.")

    # OSPF area check
    config_areas = list(dict.fromkeys(re.findall(r'area\s+(\d+)', healed_config, re.I)))
    if config_areas:
        known_areas = set()
        for inst in raw.get("ospf", {}).values():
            if isinstance(inst, dict):
                for vrf in inst.get("vrf", {}).values():
                    known_areas.update(vrf.get("area", {}).keys())
        if not known_areas and any(r.get("source_protocol") == "ospf" for r in routes.values()):
            known_areas.add("0")
        for area in config_areas:
            anorm = area.lstrip("0") or "0"
            match = any((a.lstrip("0") or "0") == anorm for a in known_areas)
            if known_areas and not match:
                warnings.append(f"OSPF area {area} not in device data. Known: {sorted(known_areas)}")
            else:
                passed.append(f"OSPF area {area} — consistent.")

    # Shutdown on critical nodes
    critical_ids = {n["id"] for n in topology.get("nodes", []) if n.get("criticality", 0) > 0.5}
    for line in config_lines:
        if "shutdown" in line:
            for nid in critical_ids:
                if nid in line:
                    issues.append(f"CRITICAL: shutdown on high-centrality node {nid} — BLOCKED.")

    # Mask sanity
    for ip, mask in re.findall(r'(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)', healed_config):
        octs = [int(x) for x in mask.split(".")]
        valid = all(o in {0, 1, 3, 7, 15, 31, 63, 127, 255, 128, 192, 224, 240, 248, 252, 254} for o in octs)
        if valid:
            passed.append(f"Mask {mask} for {ip} — valid format.")
        else:
            warnings.append(f"Mask {mask} for {ip} — unrecognised, verify manually.")

    logs.append(f"[STAGE 4] {len(issues)} issues, {len(warnings)} warnings, {len(passed)} passed.")
    return {"issues": issues, "warnings": warnings, "passed": passed,
            "safe_to_proceed": len(issues) == 0,
            "device_iface_ips": sorted(device_iface_ips),
            "device_routing_ips": sorted(device_routing_ips)}


# ══════════════════════════════════════════════════════════════════════════════
# STAGE 5: DYNAMIC LLM-DRIVEN CHANGE IMPACT DECISION
# Completely protocol-agnostic: LLM + PyATS+Genie + MCP agent data drive
# every verdict, risk score, rollback plan, and reasoning.
# NO hardcoded OSPF rules, NO static thresholds, NO protocol-specific overrides.
# ══════════════════════════════════════════════════════════════════════════════

def _classify_intent_operation(intent: str) -> dict:
    """
    Lightweight heuristic classification — does NOT contain any protocol logic.
    Only determines operation type (ADD/DELETE/MODIFY) and which protocols are
    textually mentioned in the intent. ALL impact logic lives in the LLM.
    """
    lines = intent.strip().split("\n")
    il = intent.lower()

    has_no  = any(l.strip().lower().startswith("no ") for l in lines)
    has_add = any(not l.strip().lower().startswith("no ") and l.strip()
                  for l in lines if l.strip() and not l.strip().startswith("!"))
    operation = "MODIFY" if (has_no and has_add) else ("DELETE" if has_no else ("ADD" if has_add else "UNKNOWN"))

    # Protocol detection — text-only, no impact logic
    protocols_mentioned = []
    for proto, patterns in [
        ("OSPF",    [r"ospf", r"router\s+ospf"]),
        ("BGP",     [r"bgp", r"router\s+bgp", r"remote-as"]),
        ("EIGRP",   [r"eigrp", r"router\s+eigrp"]),
        ("RIP",     [r"router\s+rip"]),
        ("ISIS",    [r"router\s+isis", r"is-is"]),
        ("STATIC",  [r"ip\s+route\s", r"ipv6\s+route\s"]),
        ("MPLS",    [r"mpls", r"label\s+protocol"]),
        ("ACL",     [r"access-list", r"ip\s+access"]),
        ("BGP_POLICY", [r"route-map", r"prefix-list", r"community"]),
        ("INTERFACE", [r"interface\s+\w", r"shutdown", r"ip\s+address"]),
        ("VPN",     [r"vrf", r"vpn"]),
        ("QOS",     [r"policy-map", r"class-map", r"service-policy"]),
    ]:
        if any(re.search(p, il) for p in patterns):
            protocols_mentioned.append(proto)

    destructive_lines = [l.strip() for l in lines if l.strip().lower().startswith("no ")]
    additive_lines    = [l.strip() for l in lines
                         if l.strip() and not l.strip().lower().startswith("no ")
                         and not l.strip().startswith("!")]

    return {
        "operation":          operation,
        "protocols_mentioned": protocols_mentioned,
        "primary_protocol":   protocols_mentioned[0] if protocols_mentioned else "UNKNOWN",
        "destructive_lines":  destructive_lines,
        "additive_lines":     additive_lines,
        "line_count":         len([l for l in lines if l.strip() and not l.strip().startswith("!")]),
        "has_destructive":    len(destructive_lines) > 0,
    }


def _build_dynamic_device_context(intent: str, raw: dict, topology: dict,
                                   validation: dict, logs: list) -> dict:
    """
    Build a complete, protocol-agnostic device state context for the LLM.
    Collects ALL protocol state from PyATS+Genie structured data via MCP.
    LLM receives this rich JSON — no protocol-specific Python logic here.
    """
    routes = (raw.get("routing", {}).get("vrf", {}).get("default", {})
                 .get("address_family", {}).get("ipv4", {}).get("routes", {}))
    iface_data = raw.get("interface", {}).get("info", {})

    # ── Route table — all protocols ───────────────────────────────────────────
    route_by_proto: dict = {}
    for pfx, r in routes.items():
        proto = r.get("source_protocol", "unknown")
        nh_list = r.get("next_hop", {}).get("next_hop_list", {})
        nhs = [v.get("next_hop", "") for v in nh_list.values() if v.get("next_hop")]
        route_by_proto.setdefault(proto, []).append({"prefix": pfx, "next_hops": nhs})
    route_summary = {p: len(v) for p, v in route_by_proto.items()}

    # ── OSPF neighbors from ALL sources (raw CLI + Genie) ────────────────────
    ospf_nbrs = _extract_ospf_neighbors_all_sources(raw)
    active_ospf = {k: v for k, v in ospf_nbrs.items()
                   if re.search(r'FULL|2WAY', str(v.get("state", "")).upper())
                   and "config-only" not in str(v.get("state", "")).lower()}
    ospf_processes = re.findall(r'router\s+ospf\s+(\d+)',
                                raw.get("running_config", ""), re.I)

    # ── BGP sessions ──────────────────────────────────────────────────────────
    bgp_nbrs = []
    for inst in raw.get("bgp", {}).get("instance", {}).values():
        for vrf_n, vrf_d in inst.get("vrf", {}).items():
            for nbr_ip, d in vrf_d.get("neighbor", {}).items():
                bgp_nbrs.append({
                    "neighbor":  nbr_ip, "vrf": vrf_n,
                    "remote_as": d.get("remote_as", ""),
                    "state":     d.get("session_state", d.get("bgp_state", "")),
                    "prefixes":  (d.get("address_family", {}).get("ipv4 unicast", {})
                                   .get("accepted_prefix_count", "")),
                })
    # Supplement from bgp_summary
    for vrf_n, vrf_d in raw.get("bgp_summary", {}).get("vrf", {}).items():
        for nbr_ip, d in vrf_d.get("neighbor", {}).items():
            if not any(b["neighbor"] == nbr_ip for b in bgp_nbrs):
                bgp_nbrs.append({
                    "neighbor": nbr_ip, "vrf": vrf_n,
                    "remote_as": d.get("remote_as", ""),
                    "state": d.get("session_state", d.get("state_pfxrcd", "")),
                    "prefixes": d.get("prefixes_received", ""),
                })
    established_bgp = [b for b in bgp_nbrs
                       if re.search(r'Establ|ESTABL|active', str(b.get("state", "")), re.I)]
    bgp_processes = re.findall(r'router\s+bgp\s+(\d+)',
                               raw.get("running_config", ""), re.I)

    # ── Interfaces ───────────────────────────────────────────────────────────
    up_ifaces, down_ifaces = [], []
    for name, d in iface_data.items():
        ips = list(d.get("ipv4", {}).keys())
        entry = {"interface": name, "ips": ips, "description": d.get("description", ""),
                 "mtu": d.get("mtu", ""), "encap": d.get("encapsulation", {}).get("encapsulation", "")}
        if d.get("oper_status") == "up":
            up_ifaces.append(entry)
        else:
            down_ifaces.append(entry)

    # ── CDP neighbors ─────────────────────────────────────────────────────────
    cdp_nbrs = []
    for idx, e in raw.get("cdp_neighbors", {}).get("index", {}).items():
        ip_info = e.get("management_addresses", {}) or e.get("entry_addresses", {})
        cdp_nbrs.append({
            "device": (e.get("device_id", "") or "").split(".")[0],
            "local_if": e.get("local_interface", ""),
            "remote_if": e.get("port_id", ""),
            "platform": e.get("platform", ""),
            "ip": list(ip_info.keys())[0] if ip_info else "",
        })

    # ── ACLs ─────────────────────────────────────────────────────────────────
    acl_names = list(raw.get("acl", {}).get("acls", {}).keys())

    # ── Running config protocol blocks ────────────────────────────────────────
    rc = raw.get("running_config", "")
    routing_processes = re.findall(r'(router\s+\w+(?:\s+\d+)?)', rc, re.I)[:10]
    passive_ifaces = re.findall(r'passive-interface\s+(\S+)', rc, re.I)
    redistribute_stmts = re.findall(r'(redistribute\s+\S+.*)', rc, re.I)[:6]

    # ── Topology/centrality ───────────────────────────────────────────────────
    critical_nodes = sorted(topology.get("nodes", []),
                            key=lambda x: x.get("criticality", 0), reverse=True)[:6]

    # ── Validation summary ────────────────────────────────────────────────────
    val_issues   = validation.get("issues", [])
    val_warnings = validation.get("warnings", [])

    return {
        "intent": intent,
        # Route table from Genie
        "route_summary":        route_summary,
        "route_by_protocol":    {p: v[:6] for p, v in route_by_proto.items()},
        "total_routes":         len(routes),
        # OSPF from all Genie sources
        "ospf_processes":       ospf_processes,
        "ospf_all_neighbors":   [{
            "id": k, "state": v.get("state"), "interface": v.get("interface"),
            "address": v.get("address"), "area": v.get("area", ""),
            "dead_timer": v.get("dead_timer"), "source": v.get("source"),
        } for k, v in ospf_nbrs.items()],
        "ospf_active_full_count": len(active_ospf),
        "ospf_active_neighbors":  [{
            "id": k, "state": v.get("state"), "interface": v.get("interface"),
            "address": v.get("address"), "area": v.get("area", ""),
        } for k, v in active_ospf.items()],
        # BGP from Genie
        "bgp_processes":          bgp_processes,
        "bgp_all_neighbors":      bgp_nbrs,
        "bgp_established_count":  len(established_bgp),
        "bgp_established":        established_bgp[:6],
        # Interface state from Genie
        "interfaces_up":          len(up_ifaces),
        "interfaces_down":        len(down_ifaces),
        "up_interfaces":          up_ifaces[:8],
        "down_interfaces":        down_ifaces[:4],
        # CDP from Genie
        "cdp_neighbors":          cdp_nbrs,
        # Config analysis
        "routing_processes":      routing_processes,
        "passive_interfaces":     passive_ifaces,
        "redistribute_stmts":     redistribute_stmts,
        "acl_names":              acl_names,
        # Topology
        "critical_nodes":         critical_nodes,
        "topology_node_count":    len(topology.get("nodes", [])),
        "topology_edge_count":    len(topology.get("edges", [])),
        # Validation
        "validation_issues":      val_issues,
        "validation_warnings":    val_warnings,
        "safe_to_proceed":        len(val_issues) == 0,
        # Offline detection
        "offline_mode":           raw.get("_offline_mode", False),
    }


def stage_llm_decision(intent, healed_config, raw, topology, validation,
                        audit_trail, provider, logs,
                        agent_risk_indicators=None, agent_results=None,
                        round_num=1):
    """
    STAGE 5: Fully dynamic, protocol-agnostic LLM-driven change impact decision.

    Architecture:
      PyATS+Genie structured data + MCP domain agent findings
      → LLM (Claude/Ollama) performs ALL impact reasoning
      → LLM outputs: verdict, risk_score, blast_radius, execution_plan, rollback

    No OSPF-specific Python logic. No hardcoded thresholds.
    The LLM IS the decision engine — informed by real device data from Genie.
    """
    logs.append("[STAGE 5] Dynamic LLM-driven decision analysis starting...")
    logs.append("[STAGE 5] Data source: PyATS+Genie structured JSON (no raw CLI to LLM)")

    # Step 1: Classify intent (text-only, no protocol logic)
    classification = _classify_intent_operation(intent)
    logs.append(f"[STAGE 5] Intent classification: op={classification['operation']} "
                f"protocols={classification['protocols_mentioned']}")

    # Step 2: Build rich device context from Genie data
    ctx = _build_dynamic_device_context(intent, raw, topology, validation, logs)

    # Log key state for audit trail
    logs.append(f"[STAGE 5] Device state (from Genie): "
                f"routes={ctx['total_routes']} "
                f"ospf_active={ctx['ospf_active_full_count']} "
                f"bgp_established={ctx['bgp_established_count']} "
                f"interfaces_up={ctx['interfaces_up']}")
    for n in ctx.get("ospf_active_neighbors", []):
        logs.append(f"[STAGE 5] Active OSPF neighbor: {n['id']} state={n['state']} "
                    f"iface={n.get('interface')} addr={n.get('address')}")
    for b in ctx.get("bgp_established", []):
        logs.append(f"[STAGE 5] Established BGP session: {b['neighbor']} AS{b.get('remote_as')} "
                    f"state={b.get('state')} prefixes={b.get('prefixes')}")

    # Step 3: Collect MCP domain agent findings
    agent_summary_for_llm = {}
    all_risks = agent_risk_indicators or []
    if agent_results:
        for agent_name, ar in agent_results.items():
            risks = ar.get("risk_indicators", [])
            analysis = ar.get("analysis", {})
            agent_summary_for_llm[agent_name] = {
                "mcp_source":  ar.get("mcp_source", "unknown"),
                "risks":       risks[:6],
                "risk_count":  len(risks),
                "analysis":    {k: v for k, v in analysis.items()
                                if k in ("neighbor_count", "full_neighbors", "established",
                                         "total", "up", "down", "total_routes",
                                         "by_protocol", "acl_count", "vlan_count", "neighbors",
                                         "interfaces", "routes")},
            }

    crit_risks = [r for r in all_risks if "CRITICAL" in str(r).upper()]
    warn_risks  = [r for r in all_risks if "WARNING" in str(r).upper()]
    logs.append(f"[STAGE 5] Agent findings: {len(crit_risks)} CRITICAL, {len(warn_risks)} WARNING")

    # Step 4: Build the LLM prompt — all data from Genie, LLM does all reasoning
    ccie_system = """You are a CCIE-certified senior network operations expert performing Change Advisory Board (CAB) review.

Your role: Assess the REAL impact of a network configuration change using structured device state data collected by PyATS+Genie via MCP.

CORE PRINCIPLES:
1. Your analysis must be SPECIFIC — cite actual neighbor IPs, interface names, prefix counts, session states from the device data provided
2. Your verdict must be BASED ON THE DATA — if active sessions/neighbors exist and the intent disrupts them, say so explicitly
3. ALL protocols matter equally — OSPF, BGP, EIGRP, RIP, STATIC, ACL, Interface — assess what the data shows
4. The intent may touch multiple protocols simultaneously — correlate all findings
5. If the device data shows no active sessions/neighbors for a protocol, acknowledge that too
6. Rollback commands must be derived from the ACTUAL device data (real process IDs, real interface names)
7. If device is offline (no Genie data collected), clearly state limited visibility and recommend live collection first"""

    device_ctx_json = json.dumps({
        "change_intent": intent,
        "intent_classification": classification,
        "device_state_from_genie": ctx,
        "mcp_agent_findings": agent_summary_for_llm,
        "critical_risk_count": len(crit_risks),
        "warning_risk_count": len(warn_risks),
        "all_risk_indicators": all_risks[:15],
        # Stage 3 healing audit — LLM can see which configs were tried and their risk scores
        "healing_audit_trail": [
            {"iteration": a["iteration"], "risk_score": a["risk_score"], "accepted": a["accepted"]}
            for a in (audit_trail or [])
        ],
        "decision_round": round_num,  # Which round of the Stage 3↔5 feedback loop
    }, indent=2, default=str)

    # Truncate to Claude-equivalent budget regardless of provider
    # (Stage 5 always targets Claude quality; Ollama fallback gets full context too)
    if len(device_ctx_json) > 12000:
        device_ctx_json = device_ctx_json[:12000] + "\n... [truncated for token budget]"

    round_ctx = (
        f"\n⚠ ROUND {round_num}/2 — Previous config was assessed as NO-GO. "
        f"This is a refined, safer config. Re-evaluate with the same rigour — "
        f"only approve if this version genuinely resolves the prior blocking concerns.\n"
        if round_num > 1 else ""
    )

    prompt = f"""NETWORK CHANGE IMPACT ASSESSMENT — CAB EXPERT REVIEW{round_ctx}
DATA SOURCE: PyATS+Genie structured JSON collected via MCP (Netmiko SSH + pyATS Telnet)
All device state data below was collected live from the device or from saved Genie snapshots.
You are the decision engine — no protocol-specific rules override you.

{'⚠ OFFLINE MODE: Device was unreachable during collection. Genie data is empty. Recommend live collection before proceeding.' if ctx.get('offline_mode') else '✓ LIVE DATA: Device state collected via MCP → Netmiko SSH → PyATS+Genie'}

STRUCTURED DEVICE STATE + AGENT FINDINGS:
{device_ctx_json}

HEALED CONFIG (what will be applied):
{healed_config[:1500] if healed_config else '(none)'}

VALIDATION RESULTS:
Issues blocking change: {ctx['validation_issues']}
Warnings: {ctx['validation_warnings']}

INSTRUCTIONS:
1. Analyze ALL protocol impact — not just one protocol. Correlate findings across OSPF, BGP, interfaces, routes.
2. Reference SPECIFIC data from the device state (real IPs, real neighbor IDs, real prefix counts, real session states)
3. Rollback commands must use ACTUAL process IDs and interface names from the device data
4. If data is empty/offline, your verdict must reflect limited visibility
5. The LLM (you) determines the verdict — there are no Python overrides

Output EXACTLY this format (no deviations, no extra text):
DECISION: GO|NO-GO|PROCEED WITH CAUTION
RISK_SCORE: 1-10
INTENT_SUMMARY: [one precise sentence describing what will actually change on the device]
CUSTOMER_REACHABILITY: IMPACTED|NOT_IMPACTED|UNKNOWN — [specific prefixes/sessions affected, cite actual data]
ROUTING_CONVERGENCE: IMPACTED|NOT_IMPACTED|UNKNOWN — [which protocol sessions drop, reconvergence time]
NETWORK_ANNOUNCEMENT: IMPACTED|NOT_IMPACTED|UNKNOWN — [which prefixes withdrawn/added from which protocol]
REDUNDANCY: IMPACTED|NOT_IMPACTED|UNKNOWN — [are backup paths available via other protocols/statics]
POLICY: NOT_IMPACTED|IMPACTED|UNKNOWN — [ACL/route-map/prefix-list effects]
SERVICE_CONTINUITY: IMPACTED|NOT_IMPACTED|UNKNOWN — [active sessions at risk, traffic black-hole risk]
BLAST_RADIUS: [count] — [list specific neighbor IPs, prefix counts, sessions affected]
EXECUTION_PLAN:
1. [pre-change: exact show commands to verify current state — use real protocol/interface names from data]
2. [change step with exact CLI from healed_config]
3. [post-change: exact verification commands]
ROLLBACK:
1. [exact CLI to undo — use real process IDs and interface names from device data]
2. [verify recovery — cite specific session/neighbor IDs to check]
REASONING: [3 sentences citing specific data: neighbor states, route counts, session states from the Genie data above. Explain WHY the verdict is GO/NO-GO based on actual protocol state]"""

    # ── Pass 1: Initial assessment ────────────────────────────────────────────
    response = call_ai(prompt, provider, system=ccie_system)
    logs.append(f"[STAGE 5] Initial assessment complete ({len(response)} chars)")

    # ── Pass 2: Self-Critique (LLM verifies its own decision against Genie facts)
    # This is the "feedback from LLM" dynamic loop: the model checks its own output
    # for hallucinations, inconsistent risk/verdict, and uncited Genie data.
    _has_fields = ('DECISION:' in response and 'RISK_SCORE:' in response
                   and 'REASONING:' in response)
    _is_consistent = True
    if _has_fields:
        _verdict_line = next((l for l in response.split('\n') if 'DECISION:' in l), '')
        _score_line   = next((l for l in response.split('\n') if 'RISK_SCORE:' in l), '')
        _score_m      = re.search(r'(\d+(?:\.\d+)?)', _score_line)
        _score_num    = float(_score_m.group(1)) if _score_m else 5.0
        _is_nogo      = 'NO-GO' in _verdict_line.upper().replace('**', '')
        # GO should score ≤6, NO-GO should score ≥4 (overlap intentional)
        _is_consistent = (not _is_nogo and _score_num <= 6) or (_is_nogo and _score_num >= 4)

    # Always critique for Claude (fast); for Ollama only if output looks wrong
    _do_critique = provider == 'claude' or not _has_fields or not _is_consistent
    if _do_critique:
        logs.append(f"[STAGE 5] Self-critique pass "
                    f"(fields_ok={_has_fields}, consistent={_is_consistent}, provider={provider})...")
        fact_sheet = json.dumps({
            "ospf_active_neighbors": [
                {"id": n["id"], "state": n["state"], "interface": n.get("interface")}
                for n in ctx["ospf_active_neighbors"][:5]
            ],
            "bgp_established": [
                {"neighbor": b["neighbor"], "state": b.get("state"),
                 "remote_as": b.get("remote_as")}
                for b in ctx["bgp_established"][:5]
            ],
            "up_interfaces": [
                {"name": i["name"], "ip": i.get("ip")}
                for i in ctx.get("up_interfaces", [])[:8]
            ],
            "total_routes":    ctx["total_routes"],
            "route_summary":   ctx["route_summary"],
            "ospf_processes":  ctx.get("ospf_processes", []),
            "offline_mode":    ctx.get("offline_mode", False),
        }, indent=2)
        critique_prompt = f"""You produced this network change assessment:

{response[:2500]}

Now VERIFY it against these ACTUAL Genie-collected device facts:
{fact_sheet}

Check for THESE specific errors:
1. Neighbor IPs in BLAST_RADIUS — are they present in the actual facts above?
2. RISK_SCORE vs DECISION: GO=1-5, PROCEED WITH CAUTION=4-7, NO-GO=6-10
3. ROLLBACK commands — do they use real process IDs and interface names from facts?
4. Protocol claims — is the cited state (FULL/Established/up) confirmed in the data?
5. REASONING — does it cite actual numbers (route count, neighbor count) from facts?

If the assessment is fully accurate → reproduce it UNCHANGED.
If corrections are needed → output the corrected version in the EXACT same format.
Output ONLY the assessment. No preamble, no commentary."""
        refined = call_ai(critique_prompt, provider, system=ccie_system)
        if 'DECISION:' in refined and 'RISK_SCORE:' in refined and len(refined) > 300:
            response = refined
            logs.append(f"[STAGE 5] Self-critique refined decision ({len(response)} chars)")
        else:
            logs.append("[STAGE 5] Self-critique: no improvement — keeping initial response")
    else:
        logs.append("[STAGE 5] Self-critique skipped (Ollama fast-path: fields present + consistent)")

    logs.append(f"[STAGE 5] Final decision ready ({len(response)} chars)")

    # Step 5: Compute blast_radius dynamically from Genie data
    # All affected entities come from real device data — no hardcoded protocol assumptions
    affected_nbrs = (
        [n["id"] for n in ctx["ospf_active_neighbors"]] +
        [b["neighbor"] for b in ctx["bgp_established"]] +
        [n["ip"] for n in ctx["cdp_neighbors"] if n.get("ip")]
    )
    affected_pfxs = (
        [r["prefix"] for proto_routes in ctx["route_by_protocol"].values()
         for r in proto_routes[:4]]
    )
    # Downstream routes via affected next-hops
    routes = (raw.get("routing", {}).get("vrf", {}).get("default", {})
                 .get("address_family", {}).get("ipv4", {}).get("routes", {}))
    downstream = []
    for pfx, r in routes.items():
        for _, nh in r.get("next_hop", {}).get("next_hop_list", {}).items():
            if nh.get("next_hop", "") in affected_nbrs:
                downstream.append(pfx)
                break
    crit_hit = [n["id"] for n in topology.get("nodes", [])
                if n.get("criticality", 0) > 0.4
                and (n["id"] in affected_nbrs or any(n["id"] in p for p in affected_pfxs))]

    blast = {
        "directly_affected_neighbors": len(ctx["ospf_active_neighbors"]) + len(ctx["bgp_established"]),
        "directly_affected_prefixes":  len(affected_pfxs),
        "downstream_prefix_count":     len(downstream),
        "downstream_prefixes_sample":  downstream[:10],
        "critical_nodes_hit":          len(crit_hit),
        "estimated_total_impact":      len(affected_pfxs) + len(downstream) + len(crit_hit) * 3,
        "ospf_sessions_at_risk":       ctx["ospf_active_full_count"],
        "bgp_sessions_at_risk":        ctx["bgp_established_count"],
        "all_affected_neighbors":      affected_nbrs[:12],
    }

    return {"raw": response, "classification": classification, "blast_radius": blast}



def _infer_op(intent):
    lines = intent.lower().split("\n")
    has_no = any(l.startswith("no ") for l in lines)
    has_add = any(l.startswith(("router ", "network ", "ip route", "interface", "neighbor ")) for l in lines)
    if has_no and has_add: return "MODIFY"
    if has_no: return "DELETE"
    if has_add: return "ADD"
    return "UNKNOWN"


def _infer_proto(intent):
    il = intent.lower()
    for p in ["ospf", "bgp", "eigrp", "rip", "isis", "mpls"]:
        if p in il: return p.upper()
    if "ip route" in il: return "STATIC"
    if "interface" in il: return "INTERFACE"
    if "access-list" in il: return "ACL"
    if "route-map" in il: return "POLICY"
    return "OTHER"


def _blast_radius(aff_pfx, aff_nbr, topology, routes, ospf_nbrs):
    downstream = []
    for pfx, r in routes.items():
        for _, nh in r.get("next_hop", {}).get("next_hop_list", {}).items():
            if nh.get("next_hop", "") in aff_nbr:
                downstream.append(pfx)
                break
    crit_hit = [n["id"] for n in topology.get("nodes", [])
                if n.get("criticality", 0) > 0.4
                and (n["id"] in aff_nbr or n["id"] in aff_pfx)]
    return {
        "directly_affected_prefixes": len(aff_pfx),
        "directly_affected_neighbors": len(aff_nbr),
        "downstream_prefix_count": len(downstream),
        "downstream_prefixes_sample": downstream[:10],
        "downstream_nodes": crit_hit,
        "critical_nodes_hit": len(crit_hit),
        "estimated_total_impact": len(aff_pfx) + len(downstream) + len(crit_hit) * 3,
    }


# ══════════════════════════════════════════════════════════════════════════════
# CONFIG SIMULATION (parent-child correlation)
# ══════════════════════════════════════════════════════════════════════════════
def simulate_config(intent, raw, provider, logs):
    """
    Simulate what the running config would look like after applying intent.
    Returns: added_lines, removed_lines, modified_sections, simulated_config
    """
    logs.append("[SIM] Config simulation starting...")
    running_config = raw.get("running_config", "")
    if not running_config:
        logs.append("[SIM] No running config available.")
        return {"error": "No running config collected. Run discovery first."}

    # Extract protocol context from running config for dynamic prompt
    rc_protocols = []
    if running_config:
        if re.search(r'router ospf', running_config, re.I): rc_protocols.append("OSPF")
        if re.search(r'router bgp', running_config, re.I): rc_protocols.append("BGP")
        if re.search(r'router eigrp', running_config, re.I): rc_protocols.append("EIGRP")
        if re.search(r'router rip', running_config, re.I): rc_protocols.append("RIP")
        if re.search(r'ip route', running_config, re.I): rc_protocols.append("STATIC")
    # Find actual routing process blocks to reference in prompt
    process_blocks = re.findall(r'(router\s+\w+\s+\d+)', running_config, re.I)[:5]
    iface_blocks = re.findall(r'(interface\s+\S+)', running_config, re.I)[:5]
    protocols_present = ", ".join(rc_protocols) if rc_protocols else "unknown"
    example_sections = (", ".join(f'"{b}"' for b in (process_blocks + iface_blocks)[:4])
                        if (process_blocks or iface_blocks) else '"<derived from config>"')

    sim_prompt = f"""You are a Cisco IOS configuration simulation engine.

CURRENT RUNNING CONFIGURATION:
{running_config}

OPERATOR INTENT (CLI to apply):
{intent}

DEVICE CONTEXT:
- Protocols present: {protocols_present}
- Routing process blocks: {[b for b in process_blocks]}
- Interface blocks: {[b for b in iface_blocks]}

TASK: Simulate what happens when this intent is applied to the running config.

Rules:
1. Respect parent-child hierarchy: changes to any "router <proto> <pid>" block affect ALL its sub-commands
2. "no" commands remove lines; adding commands add lines to the correct section
3. Show what gets REMOVED, what gets ADDED, and the FINAL simulated config
4. Parent-child impact: if any routing process block is removed — ALL sub-lines under it are also removed
5. If any interface block is removed — all its sub-commands are also removed
6. Be precise and specific — only change what the intent specifies, reference ACTUAL section names from the config above
7. Section names MUST come from the actual running-config, NOT from hypothetical examples

Output EXACTLY this format (section names must be real config sections, e.g. {example_sections}):

REMOVED_LINES:
[each line that will be removed, one per line, prefixed with "- "]

ADDED_LINES:
[each line that will be added, one per line, prefixed with "+ "]

MODIFIED_SECTIONS:
[list ACTUAL section names from the running-config that are affected]

PARENT_CHILD_IMPACTS:
[list of parent->child cascade effects using actual config section names and their sub-commands]

SIMULATED_CONFIG:
[the complete resulting configuration after applying the intent]"""

    sim_system = (
        "You are a Cisco IOS configuration simulation engine. You output ONLY the exact section headers "
        "requested — no prose, no explanation outside those sections. Be precise and complete."
    )
    response = call_ai(sim_prompt, provider, system=sim_system)
    logs.append("[SIM] Simulation complete.")

    # Parse simulation output
    def extract_section(text, header, next_headers):
        pattern = re.compile(rf'^{re.escape(header)}\s*\n([\s\S]*?)(?=\n(?:{"|".join(re.escape(h) for h in next_headers)})|\Z)', re.M)
        m = pattern.search(text)
        return m.group(1).strip() if m else ""

    all_headers = ["REMOVED_LINES:", "ADDED_LINES:", "MODIFIED_SECTIONS:", "PARENT_CHILD_IMPACTS:", "SIMULATED_CONFIG:"]

    removed_raw   = extract_section(response, "REMOVED_LINES:", all_headers[1:])
    added_raw     = extract_section(response, "ADDED_LINES:", all_headers[2:])
    modified_raw  = extract_section(response, "MODIFIED_SECTIONS:", all_headers[3:])
    parent_raw    = extract_section(response, "PARENT_CHILD_IMPACTS:", all_headers[4:])
    simulated_raw = extract_section(response, "SIMULATED_CONFIG:", [])

    removed_lines = [l[2:].strip() for l in removed_raw.split("\n") if l.strip().startswith("- ")]
    added_lines   = [l[2:].strip() for l in added_raw.split("\n")   if l.strip().startswith("+ ")]
    modified_sections = [l.strip() for l in modified_raw.split("\n") if l.strip()]
    parent_impacts    = [l.strip() for l in parent_raw.split("\n")   if l.strip()]

    # Generate diff-style view
    diff_lines = []
    running_lines = running_config.split("\n")
    for line in running_lines:
        stripped = line.strip()
        if any(stripped in rl or rl in stripped for rl in removed_lines):
            diff_lines.append({"type": "removed", "line": line, "indent": len(line) - len(line.lstrip())})
        else:
            diff_lines.append({"type": "unchanged", "line": line, "indent": len(line) - len(line.lstrip())})
    for line in added_lines:
        diff_lines.append({"type": "added", "line": line, "indent": len(line) - len(line.lstrip())})

    return {
        "removed_lines": removed_lines,
        "added_lines": added_lines,
        "modified_sections": modified_sections,
        "parent_child_impacts": parent_impacts,
        "simulated_config": simulated_raw or response,
        "diff_lines": diff_lines,
        "raw_response": response,
        "running_config": running_config,
    }


# ══════════════════════════════════════════════════════════════════════════════
# GENIE DIFF ENGINE — pre/post state comparison (NO LLM needed)
# ══════════════════════════════════════════════════════════════════════════════

def _snapshot_key(port, label: str, feature: str) -> str:
    return f"{port}:{label}:{feature}"


def take_state_snapshot(port, label: str, features: list, dev, logs: list) -> dict:
    """
    Capture Genie learn() state for each feature and store in STATE_SNAPSHOTS.
    label should be 'pre' or 'post'.
    """
    summary = {}
    for feat in features:
        try:
            learned = dev.learn(feat)
            data = learned.to_dict() if hasattr(learned, 'to_dict') else _safe_to_dict_collect(learned)
            STATE_SNAPSHOTS[_snapshot_key(port, label, feat)] = data
            summary[feat] = {"status": "ok", "keys": list(data.keys())[:5]}
            logs.append(f"[SNAPSHOT] {label}:{feat} captured")
        except Exception as e:
            summary[feat] = {"status": f"error: {str(e)[:80]}"}
            logs.append(f"[SNAPSHOT] {label}:{feat} failed: {str(e)[:60]}")
    return summary


def genie_diff_features(port, features: list, logs: list) -> dict:
    """
    Run Genie Diff between pre and post snapshots for each feature.
    Returns structured diff: {feature: {added, removed, modified, risk}}
    """
    results = {}
    for feat in features:
        pre_key  = _snapshot_key(port, "pre",  feat)
        post_key = _snapshot_key(port, "post", feat)
        pre  = STATE_SNAPSHOTS.get(pre_key)
        post = STATE_SNAPSHOTS.get(post_key)

        if pre is None or post is None:
            results[feat] = {"error": f"Missing snapshot: pre={pre is not None} post={post is not None}"}
            continue

        if PYATS_AVAILABLE:
            try:
                diff_obj = GenieDiff(pre, post)
                diff_obj.findDiff()
                raw_diff_str = str(diff_obj)
                diff_result  = _parse_genie_diff_string(raw_diff_str)
                diff_result["raw_diff"] = raw_diff_str
                logs.append(f"[DIFF] {feat}: +{diff_result['counts']['added']} "
                            f"-{diff_result['counts']['removed']} "
                            f"~{diff_result['counts']['modified']}")
            except Exception as e:
                diff_result = _python_fallback_diff(pre, post)
                diff_result["_genie_error"] = str(e)[:100]
                logs.append(f"[DIFF] {feat}: Genie Diff failed, using fallback: {str(e)[:60]}")
        else:
            diff_result = _python_fallback_diff(pre, post)
            logs.append(f"[DIFF] {feat}: pyATS unavailable, using Python fallback diff")

        diff_result["risk"] = _assess_diff_risk(diff_result, feat)
        results[feat] = diff_result

    return results


def _parse_genie_diff_string(diff_str: str) -> dict:
    """Parse Genie Diff string into added/removed/modified lists."""
    added, removed, modified = [], [], []
    for line in diff_str.split("\n"):
        s = line.strip()
        if not s:
            continue
        if s.startswith("+") and not s.startswith("+++"):
            added.append(s[1:].strip())
        elif s.startswith("-") and not s.startswith("---"):
            removed.append(s[1:].strip())
        elif ":" in s and not s.startswith(("+", "-")):
            modified.append(s)
    return {
        "added":    added[:100],
        "removed":  removed[:100],
        "modified": modified[:100],
        "counts":   {"added": len(added), "removed": len(removed), "modified": len(modified)},
        "_engine":  "genie_diff",
    }


def _python_fallback_diff(pre: dict, post: dict) -> dict:
    """Python-based recursive dict diff as fallback."""
    added, removed, modified = [], [], []

    def _recurse(a, b, path=""):
        if isinstance(a, dict) and isinstance(b, dict):
            for k in set(list(a.keys()) + list(b.keys())):
                np = f"{path}.{k}" if path else str(k)
                if k not in a:
                    added.append(np)
                elif k not in b:
                    removed.append(np)
                else:
                    _recurse(a[k], b[k], np)
        elif a != b:
            modified.append(f"{path}: {str(a)[:50]} → {str(b)[:50]}")

    _recurse(pre, post)
    return {
        "added":    added[:100],
        "removed":  removed[:100],
        "modified": modified[:100],
        "counts":   {"added": len(added), "removed": len(removed), "modified": len(modified)},
        "_engine":  "python_fallback",
    }


def _assess_diff_risk(diff: dict, feature: str) -> dict:
    """Assess risk level from a diff result."""
    added   = diff.get("added",   [])
    removed = diff.get("removed", [])
    modified = diff.get("modified", [])
    counts  = diff.get("counts",  {})

    score    = 0.0
    findings = []

    nbr_removed = [r for r in removed if re.search(r'neighbor|state|adjacen', str(r).lower())]
    if nbr_removed:
        score += 0.5 * min(len(nbr_removed), 4)
        findings.append(f"CRITICAL: {len(nbr_removed)} neighbor state entries removed — adjacency loss")

    full_removed = [r for r in removed + modified if "FULL" in str(r)]
    if full_removed:
        score += 0.4
        findings.append(f"CRITICAL: FULL state adjacency removed — routing outage expected")

    route_removed = [r for r in removed if re.search(r'\d+\.\d+\.\d+\.\d+', str(r))]
    if route_removed:
        score += 0.1 * min(len(route_removed), 5)
        findings.append(f"WARNING: {len(route_removed)} route entries removed")

    intf_down = [m for m in modified if re.search(r'down|admin', str(m).lower())]
    if intf_down:
        score += 0.2
        findings.append(f"WARNING: Interface state changes: {intf_down[:3]}")

    total = counts.get("added", 0) + counts.get("removed", 0) + counts.get("modified", 0)
    if total == 0:
        return {"verdict": "NO_CHANGE", "score": 0.0, "findings": ["No state change detected"]}

    score = min(score, 1.0)
    verdict = "CRITICAL" if score >= 0.6 else "WARNING" if score >= 0.25 else "SAFE"
    if not findings:
        findings = [f"{total} state changes detected ({feature})"]

    return {"verdict": verdict, "score": round(score, 3), "findings": findings}


# ══════════════════════════════════════════════════════════════════════════════
# MCP EXECUTION ENGINE  (True MCP: Netmiko → Genie → structured JSON)
# ══════════════════════════════════════════════════════════════════════════════
# Architecture:
#   Agent calls MCP tool (never connects to device directly)
#   MCP → Netmiko SSH executes CLI
#   MCP → Genie parses output → structured JSON
#   Agent receives JSON only — Claude NEVER sees raw CLI
#
# MCP Tools:
#   build_testbed         → Netmiko SSH + pyATS Telnet sessions
#   run_show_and_parse    → Netmiko executes → Genie parses → JSON
#   learn_feature_state   → Genie Learn API → full protocol state model
#   compare_snapshots     → Genie Diff(pre, post) → added/removed/modified
#   take_snapshot         → named state capture for diff comparison
# ─────────────────────────────────────────────────────────────────────────────

class MCPExecutionEngine:
    """
    Real MCP Execution Gateway — the central execution layer.
    Agents call these MCP tools. They never connect to devices directly.
    All CLI execution: Netmiko SSH → Genie Parser → structured JSON returned to agent.
    """
    def __init__(self, port: int, logs: list):
        self.port           = port
        self.logs           = logs
        self._dev           = None     # pyATS device (Genie Learn/Parse)
        self._netmiko       = None     # Netmiko SSH session (CLI execution)
        self._connected     = False    # pyATS connected
        self._ssh_connected = False    # Netmiko SSH connected

    # ─── MCP Tool: build_testbed ──────────────────────────────────────────────
    def build_testbed(self, channel: str = "all") -> dict:
        """
        MCP Tool: build_testbed
        Establishes Netmiko SSH and/or pyATS Telnet connectivity.
        Returns: {status, channels, hostname, port}
        Called by Supervisor Agent before dispatching domain agents.
        """
        result = {"port": self.port, "channels": [], "hostname": "unknown"}
        p = self.port

        # ── Netmiko SSH (primary execution channel) ──────────────────────────
        _p_key = str(p)
        if str(p) in _TELNET_ONLY_PORTS:
            self.logs.append(f"[MCP:build_testbed] SSH skipped — port {p} is Telnet-only (cached).")
        elif NETMIKO_AVAILABLE and channel in ("ssh", "all"):
            try:
                existing = NETMIKO_SESSIONS.get(_p_key)
                if existing:
                    try:
                        existing.send_command("", read_timeout=5)
                        self._netmiko = existing
                        self._ssh_connected = True
                        result["channels"].append("ssh")
                        self.logs.append(f"[MCP:build_testbed] SSH: reused session port={p}")
                    except Exception:
                        NETMIKO_SESSIONS.pop(_p_key, None)

                if not self._ssh_connected:
                    nm = ConnectHandler(
                        device_type="cisco_ios",
                        host=WINDOWS_IP,
                        port=p,
                        username=GNS3_USERNAME,
                        password=GNS3_PASSWORD,
                        timeout=10,
                        banner_timeout=5,   # fast-fail if port speaks Telnet (0xff IAC)
                        session_log=None,
                    )
                    self._netmiko = nm
                    NETMIKO_SESSIONS[_p_key] = nm
                    self._ssh_connected = True
                    result["channels"].append("ssh")
                    self.logs.append(f"[MCP:build_testbed] SSH connected via Netmiko port={p}")
            except Exception as e:
                err_str = str(e)
                if '0xff' in err_str or 'banner' in err_str.lower():
                    _TELNET_ONLY_PORTS.add(_p_key)   # cache: skip SSH next time
                    self.logs.append(f"[MCP:build_testbed] Port {p} speaks Telnet — SSH skipped in future.")
                else:
                    self.logs.append(f"[MCP:build_testbed] SSH unavailable: {err_str[:80]}")

        # ── pyATS Telnet (Genie Learn/Parse channel) ──────────────────────────
        if PYATS_AVAILABLE and channel in ("telnet", "all"):
            try:
                dev = get_device_obj(p)
                dev.connect(log_stdout=False, dialog=gns3_dialog, learn_hostname=True)
                dev.execute('terminal length 0')
                self._dev       = dev
                self._connected = True
                result["channels"].append("telnet")
                result["hostname"] = getattr(dev, 'hostname', 'unknown')
                self.logs.append(f"[MCP:build_testbed] Telnet/pyATS connected hostname={result['hostname']}")
            except Exception as e:
                self.logs.append(f"[MCP:build_testbed] Telnet unavailable: {str(e)[:80]}")

        # ── Offline fallback: cached inventory ───────────────────────────────
        if not result["channels"]:
            saved = SAVED_INVENTORY.get(str(p))
            if saved:
                result["channels"].append("cached")
                result["hostname"]  = "offline-cached"
                result["status"]    = "cached_only"
                self.logs.append(f"[MCP:build_testbed] No live connection — using cached inventory (offline mode)")
            else:
                result["status"] = "no_connection"
                self.logs.append(f"[MCP:build_testbed] WARNING: no connection and no cached data")
                return result

        result["status"] = "connected"
        return result

    # ─── MCP Tool: run_show_and_parse ─────────────────────────────────────────
    def run_show_and_parse(self, command: str) -> dict:
        """
        MCP Tool: run_show_and_parse
        Step 1: Netmiko SSH executes the show command → raw CLI output
        Step 2: pyATS Genie parses output → structured JSON dict
        Agent receives ONLY structured JSON. Claude never sees raw CLI.

        Agent → MCP.run_show_and_parse("show ip ospf neighbor")
              → Netmiko executes on device
              → Genie parses: {"interfaces": {"Gi0/0.23": {"neighbors": {...}}}}
              → Returns structured dict to agent
        """
        self.logs.append(f"[MCP:run_show_and_parse] Executing: '{command}'")
        raw_output  = None
        channel_used = "none"

        # Step 1a: Netmiko SSH execution (preferred — fast, reliable)
        if self._netmiko and self._ssh_connected:
            try:
                raw_output   = self._netmiko.send_command(command, read_timeout=45)
                channel_used = "netmiko_ssh"
                self.logs.append(f"[MCP:run_show_and_parse] Netmiko SSH got {len(raw_output)} chars")
            except Exception as e:
                self.logs.append(f"[MCP:run_show_and_parse] Netmiko error: {str(e)[:60]}")

        # Step 1b: pyATS Telnet fallback
        if raw_output is None and self._dev and self._connected:
            try:
                raw_output   = self._dev.execute(command)
                channel_used = "pyats_telnet"
                self.logs.append(f"[MCP:run_show_and_parse] pyATS Telnet got {len(raw_output)} chars")
            except Exception as e:
                self.logs.append(f"[MCP:run_show_and_parse] pyATS error: {str(e)[:60]}")

        # Step 1c: Cached inventory fallback
        if raw_output is None:
            cached = self._get_cached_for_command(command)
            if cached:
                self.logs.append(f"[MCP:run_show_and_parse] Cached data returned for '{command}'")
                return {"structured": cached, "channel": "cached", "command": command}
            return {"structured": {}, "channel": "none", "command": command,
                    "error": "no live connection and no cached data"}

        # Step 2: Genie parse → structured JSON (agent never sees raw_output)
        structured = {}
        if self._dev and PYATS_AVAILABLE:
            try:
                structured = self._dev.parse(command)
                self.logs.append(f"[MCP:run_show_and_parse] Genie parsed → keys: {list(structured.keys())[:6]}")
            except Exception as e:
                self.logs.append(f"[MCP:run_show_and_parse] Genie parse failed ({str(e)[:50]}) — text fallback")
                # Minimal structure so agent still gets something
                structured = {"_raw_text": raw_output[:1500], "_parse_error": str(e)[:80]}
        else:
            structured = {"_raw_text": raw_output[:1500]}

        return {"structured": structured, "channel": channel_used, "command": command}

    # ─── MCP Tool: learn_feature_state ───────────────────────────────────────
    def learn_feature_state(self, feature: str) -> dict:
        """
        MCP Tool: learn_feature_state
        Builds complete operational model using Genie Learn API.
        Preferred over run_show_and_parse — gives full protocol state in one call.
        Features: interface, routing, ospf, bgp, acl, vrf, cdp, vlan, platform, lldp

        Agent → MCP.learn_feature_state("ospf")
              → device.learn("ospf")  [Genie Learn API]
              → Returns complete OSPF operational model as structured JSON
        """
        self.logs.append(f"[MCP:learn_feature_state] feature='{feature}' via Genie Learn API")

        # Live Genie Learn (preferred)
        if self._dev and self._connected:
            try:
                learned = self._dev.learn(feature)
                data    = _safe_to_dict(learned)
                self.logs.append(f"[MCP:learn_feature_state] Genie learned '{feature}': {len(str(data))} chars")
                # Update cache
                saved = SAVED_INVENTORY.get(str(self.port))
                if saved:
                    saved["raw_twin"][feature] = data
                return {"feature": feature, "data": data, "source": "genie_live"}
            except Exception as e:
                self.logs.append(f"[MCP:learn_feature_state] Genie learn '{feature}' failed: {str(e)[:80]}")

        # Cached fallback
        saved = SAVED_INVENTORY.get(str(self.port))
        if saved:
            raw  = saved.get("raw_twin", {})
            data = raw.get(feature, {})
            if data:
                self.logs.append(f"[MCP:learn_feature_state] Cached '{feature}' returned ({len(str(data))} chars)")
                return {"feature": feature, "data": data, "source": "cached"}

        self.logs.append(f"[MCP:learn_feature_state] No data for '{feature}'")
        return {"feature": feature, "data": {}, "source": "none",
                "error": f"No live connection and no cached data for '{feature}'"}

    # ─── MCP Tool: compare_snapshots ─────────────────────────────────────────
    def compare_snapshots(self, feature: str, pre_label: str = "pre", post_label: str = "post") -> dict:
        """
        MCP Tool: compare_snapshots
        Runs Genie Diff between two named state snapshots.
        Returns deterministic structural diff: added/removed/modified.
        """
        self.logs.append(f"[MCP:compare_snapshots] {feature}: '{pre_label}' → '{post_label}'")
        pre_key  = _snapshot_key(self.port, pre_label, feature)
        post_key = _snapshot_key(self.port, post_label, feature)
        pre      = STATE_SNAPSHOTS.get(pre_key, {})
        post     = STATE_SNAPSHOTS.get(post_key, {})

        if not pre and not post:
            return {"feature": feature, "error": "No snapshots found — take pre/post snapshots first"}
        if not pre:
            return {"feature": feature, "error": f"No '{pre_label}' snapshot"}
        if not post:
            return {"feature": feature, "error": f"No '{post_label}' snapshot"}

        # Genie Diff
        diff_result = {}
        if PYATS_AVAILABLE:
            try:
                diff_obj = GenieDiff(pre, post)
                diff_obj.findDiff()
                raw_diff = str(diff_obj)
                diff_result = _parse_genie_diff_string(raw_diff)
                diff_result["engine"]   = "genie_diff"
                diff_result["raw_diff"] = raw_diff[:1000]
                added   = diff_result.get("counts", {}).get("added", 0)
                removed = diff_result.get("counts", {}).get("removed", 0)
                self.logs.append(f"[MCP:compare_snapshots] Genie Diff '{feature}': +{added} -{removed}")
            except Exception as e:
                self.logs.append(f"[MCP:compare_snapshots] Genie Diff error: {str(e)[:80]}")
                diff_result = _python_fallback_diff(pre, post)
                diff_result["engine"] = "python_fallback"
        else:
            diff_result = _python_fallback_diff(pre, post)
            diff_result["engine"] = "python_fallback"

        risk = _assess_diff_risk(diff_result, feature)
        return {
            "feature":  feature,
            "added":    diff_result.get("added", []),
            "removed":  diff_result.get("removed", []),
            "modified": diff_result.get("modified", []),
            "counts":   diff_result.get("counts", {}),
            "risk":     risk,
            "engine":   diff_result.get("engine", "unknown"),
        }

    def take_snapshot(self, label: str, features: list) -> dict:
        """
        MCP Tool: take_snapshot
        Captures named state snapshot (pre/post) using learn_feature_state.
        Used before and after config changes for Genie Diff comparison.
        """
        summary = {}
        for feat in features:
            r = self.learn_feature_state(feat)
            if r.get("data"):
                STATE_SNAPSHOTS[_snapshot_key(self.port, label, feat)] = r["data"]
                summary[feat] = {"status": "captured", "source": r.get("source", "unknown")}
                self.logs.append(f"[MCP:take_snapshot] '{label}/{feat}' captured from {r.get('source')}")
            else:
                summary[feat] = {"status": "empty"}
        return {"label": label, "features": summary}

    def disconnect(self):
        """Clean teardown of all MCP sessions."""
        if self._dev:
            try: self._dev.disconnect()
            except: pass
        if self._netmiko:
            try: self._netmiko.disconnect()
            except: pass

    def _get_cached_for_command(self, command: str):
        """Map common show commands to cached inventory data (offline mode)."""
        saved = SAVED_INVENTORY.get(str(self.port))
        if not saved:
            return None
        raw = saved.get("raw_twin", {})
        cmd = command.lower().strip()
        for pattern, key in [
            ("show ip ospf neighbor",        "ospf_neighbors_detail"),
            ("show ip ospf nei",             "ospf_neighbors_detail"),
            ("show ip interface brief",      "ip_interface_brief"),
            ("show ipv6 interface brief",    "ipv6_interface_brief"),
            ("show ip bgp summary",          "bgp_summary"),
            ("show bgp all summary",         "bgp_summary"),
            ("show ip bgp neighbors",        "bgp_neighbors_detail"),
            ("show cdp neighbors detail",    "cdp_neighbors"),
            ("show cdp neighbors",           "cdp_neighbors"),
            ("show lldp neighbors",          "lldp_neighbors"),
            ("show ip route",               "routing"),
            ("show ip access-lists",        "ip_access_lists"),
            ("show vlan",                   "vlan"),
            ("show running-config",         "running_config"),
            ("show version",                "platform"),
        ]:
            if cmd.startswith(pattern) and raw.get(key):
                return raw[key]
        return None


def _safe_to_dict(obj):
    """Recursively convert Genie OpsObjects to plain Python dicts."""
    try:
        if hasattr(obj, 'to_dict'):
            return obj.to_dict()
        if hasattr(obj, '__dict__'):
            return {k: _safe_to_dict(v) for k, v in obj.__dict__.items()
                    if not k.startswith('_')}
        if isinstance(obj, dict):
            return {k: _safe_to_dict(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [_safe_to_dict(i) for i in obj]
        return obj
    except Exception:
        return str(obj)


# ══════════════════════════════════════════════════════════════════════════════
# DOMAIN EXPERT AGENTS  (Agents call MCP tools — never devices directly)
# ══════════════════════════════════════════════════════════════════════════════
# Agent Decision-Making Model (per spec):
#   1. Understand intent
#   2. Map intent → impacted features
#   3. Identify state variables needed
#   4. Request data via MCP tools
#   5. Correlate structured data (JSON only — no raw CLI)
#   6. Evaluate risks
#   7. Return JSON result to Supervisor Agent
# ─────────────────────────────────────────────────────────────────────────────

class DomainAgent:
    """Base class: all domain agents use MCP for data — never direct device access."""
    name                    = "base"
    protocol                = "base"
    learn_object            = "interface"
    critical_show_commands  = []

    def __init__(self, mcp: MCPExecutionEngine, intent: str, logs: list):
        self.mcp    = mcp        # ALL data requests go through here
        self.intent = intent
        self.logs   = logs
        self._state = {}

    def run(self) -> dict:
        """
        Full agent execution lifecycle:
          1. Map intent → features
          2. Request state via MCP tools (not direct device)
          3. Correlate + evaluate
          4. Return structured JSON to Supervisor
        """
        relevant = self._is_intent_relevant()

        # Step 4: Request data via MCP → learn_feature_state (Genie Learn API)
        self.logs.append(
            f"[AGENT:{self.name.upper()}] → MCP.learn_feature_state('{self.learn_object}')"
        )
        state_result = self.mcp.learn_feature_state(self.learn_object)
        self._state  = state_result.get("data", {})
        source       = state_result.get("source", "unknown")
        self.logs.append(
            f"[AGENT:{self.name.upper()}] ← MCP returned {len(str(self._state))} chars [source={source}]"
        )

        # Step 4 (supplementary): run_show_and_parse for verification commands
        parsed_cmds = {}
        for cmd in self.critical_show_commands[:2]:
            r = self.mcp.run_show_and_parse(cmd)
            s = r.get("structured", {})
            if s and "_raw_text" not in s:
                parsed_cmds[cmd] = s
                self.logs.append(
                    f"[AGENT:{self.name.upper()}] → MCP.run_show_and_parse('{cmd}')"
                    f" ← {list(s.keys())[:4]}"
                )

        # Steps 5-6: Correlate JSON + evaluate risks
        analysis        = self._extract_analysis(self._state, parsed_cmds)
        risk_indicators = self._evaluate_risks(analysis, parsed_cmds)

        # Step 7: Return structured JSON to Supervisor Agent
        return {
            "agent":                 self.name,
            "protocol":              self.protocol,
            "learn_object":          self.learn_object,
            "mcp_source":            source,
            "mcp_tools_called":      ["learn_feature_state", "run_show_and_parse"],
            "critical_show_commands": self.critical_show_commands,
            "relevant_to_intent":    relevant,
            "analysis":              analysis,
            "risk_indicators":       risk_indicators,
            "risk_count":            len(risk_indicators),
        }

    def _is_intent_relevant(self) -> bool:
        return True

    def _extract_analysis(self, state: dict, parsed_cmds: dict) -> dict:
        return {}

    def _evaluate_risks(self, analysis: dict, parsed_cmds: dict) -> list:
        return []


class OSPFAgent(DomainAgent):
    name            = "ospf"
    protocol        = "ospf"
    learn_object    = "ospf"
    critical_show_commands = [
        "show ip ospf neighbor",
        "show ip ospf",
        "show ip ospf database",
        "show ip route ospf",
    ]

    def _is_intent_relevant(self) -> bool:
        return bool(re.search(
            r'ospf|router\s+ospf|no\s+router\s+ospf|network.*area|area|redistribute.*ospf|passive|hello|dead',
            self.intent.lower()))

    def _extract_analysis(self, state: dict, parsed_cmds: dict) -> dict:
        # Extract from Genie-structured data returned by MCP
        combined = {"ospf": state,
                    "ospf_neighbors_detail": parsed_cmds.get("show ip ospf neighbor", {})}
        nbrs_raw   = _extract_ospf_neighbors_all_sources(combined)
        neighbors  = []
        for nbr_id, d in nbrs_raw.items():
            neighbors.append({
                "neighbor_id": nbr_id,
                "state":       d.get("state", ""),
                "interface":   d.get("interface", ""),
                "area":        d.get("area", "0"),
                "dead_timer":  d.get("dead_timer", ""),
                "address":     d.get("address", ""),
            })
        processes = list(state.keys()) if isinstance(state, dict) else []
        areas = set()
        for proc in (state.values() if isinstance(state, dict) else []):
            for vrf_d in (proc.get("vrf", {}) if isinstance(proc, dict) else {}).values():
                for a in vrf_d.get("area", {}).keys():
                    areas.add(a)
        return {
            "neighbor_count": len(neighbors),
            "full_neighbors": len([n for n in neighbors if "FULL" in str(n["state"]).upper()]),
            "neighbors":      neighbors,
            "process_ids":    processes,
            "areas":          sorted(areas),
        }

    def _evaluate_risks(self, analysis: dict, parsed_cmds: dict) -> list:
        risk = []
        full = [n for n in analysis.get("neighbors", [])
                if "FULL" in str(n.get("state", "")).upper()]
        il   = self.intent.lower()
        if full and re.search(r'no\s+router\s+ospf|no\s+network.*area|shutdown.*ospf', il):
            risk.append(f"CRITICAL: {len(full)} FULL-state OSPF neighbor(s) WILL DROP — routing outage")
            for n in full:
                risk.append(
                    f"  ↳ Neighbor {n['neighbor_id']} on {n.get('interface','')} "
                    f"(area {n.get('area','')}) → adjacency LOST"
                )
        if not analysis.get("neighbors") and self._is_intent_relevant():
            risk.append("INFO: No OSPF neighbors found — process may be inactive")
        return risk


class BGPAgent(DomainAgent):
    name            = "bgp"
    protocol        = "bgp"
    learn_object    = "bgp"
    critical_show_commands = [
        "show ip bgp summary",
        "show ip bgp neighbors",
        "show bgp all summary",
        "show ip bgp",
    ]

    def _is_intent_relevant(self) -> bool:
        return bool(re.search(
            r'bgp|router\s+bgp|no\s+router\s+bgp|neighbor.*remote-as|neighbor.*shutdown|redistribute.*bgp',
            self.intent.lower()))

    def _extract_analysis(self, state: dict, parsed_cmds: dict) -> dict:
        neighbors = []
        for inst in state.get("instance", {}).values():
            for vrf_n, vrf_d in inst.get("vrf", {}).items():
                for nbr_ip, d in vrf_d.get("neighbor", {}).items():
                    neighbors.append({
                        "neighbor":  nbr_ip,
                        "vrf":       vrf_n,
                        "remote_as": d.get("remote_as", ""),
                        "state":     d.get("session_state", d.get("bgp_state", "")),
                        "prefixes":  d.get("address_family", {}).get("ipv4 unicast", {})
                                       .get("accepted_prefix_count", ""),
                        "uptime":    d.get("up_time", ""),
                    })
        for cmd_r in parsed_cmds.values():
            for vrf_n, vrf_d in cmd_r.get("vrf", {}).items():
                for nbr_ip, d in vrf_d.get("neighbor", {}).items():
                    if not any(n["neighbor"] == nbr_ip for n in neighbors):
                        neighbors.append({
                            "neighbor":  nbr_ip,
                            "vrf":       vrf_n,
                            "remote_as": d.get("remote_as", ""),
                            "state":     d.get("session_state", ""),
                            "prefixes":  d.get("prefixes_received", ""),
                            "uptime":    d.get("up_down", ""),
                        })
        established = [n for n in neighbors
                       if re.search(r'Establ|ESTABL', str(n.get("state", "")))]
        return {
            "neighbor_count": len(neighbors),
            "established":    len(established),
            "neighbors":      neighbors,
        }

    def _evaluate_risks(self, analysis: dict, parsed_cmds: dict) -> list:
        risk = []
        est  = [n for n in analysis.get("neighbors", [])
                if re.search(r'Establ|ESTABL', str(n.get("state", "")))]
        il   = self.intent.lower()
        if est and re.search(r'no\s+router\s+bgp|neighbor.*shutdown|no\s+neighbor|clear.*bgp', il):
            risk.append(f"CRITICAL: {len(est)} Established BGP session(s) WILL DROP")
            for n in est:
                risk.append(
                    f"  ↳ Peer {n['neighbor']} AS{n.get('remote_as','')} "
                    f"({n.get('prefixes','')} prefixes) → session RESET"
                )
        return risk


class InterfaceAgent(DomainAgent):
    name            = "interface"
    protocol        = "interface"
    learn_object    = "interface"
    critical_show_commands = [
        "show ip interface brief",
        "show ipv6 interface brief",
        "show interfaces",
        "show interfaces status",
    ]

    def _is_intent_relevant(self) -> bool:
        return bool(re.search(
            r'interface|shutdown|no\s+shutdown|ip\s+address|bandwidth|mtu|encapsulation'
            r'|subinterface|gigabit|loopback|serial|fastethernet',
            self.intent.lower()))

    def _extract_analysis(self, state: dict, parsed_cmds: dict) -> dict:
        iface_data = state.get("info", {})
        interfaces = []
        for name, d in iface_data.items():
            ipv4 = list(d.get("ipv4", {}).keys())
            ipv6 = list(d.get("ipv6", {}).keys()) if d.get("ipv6") else []
            interfaces.append({
                "interface":   name,
                "ipv4":        ipv4,
                "ipv6":        ipv6,
                "status":      d.get("oper_status", "unknown"),
                "protocol":    d.get("line_protocol", d.get("oper_status", "unknown")),
                "description": d.get("description", ""),
                "mtu":         d.get("mtu", ""),
                "bandwidth":   d.get("bandwidth", ""),
                "enabled":     d.get("enabled", True),
            })
        up   = [i for i in interfaces if i["status"] == "up"]
        down = [i for i in interfaces if i["status"] != "up"]
        return {"total": len(interfaces), "up": len(up), "down": len(down), "interfaces": interfaces}

    def _evaluate_risks(self, analysis: dict, parsed_cmds: dict) -> list:
        risk = []
        il   = self.intent.lower()
        for iface in analysis.get("interfaces", []):
            if iface["status"] == "up" and iface["interface"].lower() in il:
                if re.search(r'shutdown|no\s+ip\s+address', il):
                    ips = ', '.join(iface.get("ipv4", []) + iface.get("ipv6", []))
                    risk.append(f"WARNING: {iface['interface']} (IPs: {ips or 'none'}) → will go DOWN")
        return risk


class ACLAgent(DomainAgent):
    name            = "acl"
    protocol        = "acl"
    learn_object    = "acl"
    critical_show_commands = [
        "show ip access-lists",
        "show access-lists",
        "show running-config | include ip access",
    ]

    def _is_intent_relevant(self) -> bool:
        return bool(re.search(
            r'access-list|access-group|acl|permit|deny|ip\s+access',
            self.intent.lower()))

    def _extract_analysis(self, state: dict, parsed_cmds: dict) -> dict:
        acls = []
        for aname, d in state.get("acls", {}).items():
            entries = []
            for seq, ace in sorted(
                d.get("aces", {}).items(),
                key=lambda x: int(x[0]) if str(x[0]).isdigit() else 0
            ):
                entries.append({
                    "sequence": seq,
                    "action":   ace.get("actions", {}).get("forwarding", ""),
                    "src":      ace.get("matches", {}).get("l3", {}).get("ipv4", {})
                                   .get("source_network", {}).get("source_network", "any"),
                    "dst":      ace.get("matches", {}).get("l3", {}).get("ipv4", {})
                                   .get("destination_network", {}).get("destination_network", "any"),
                    "hits":     ace.get("statistics", {}).get("matched_packets", 0),
                })
            acls.append({"acl_name": aname, "type": d.get("type", ""), "entries": entries})
        return {"acl_count": len(acls), "acls": acls}

    def _evaluate_risks(self, analysis: dict, parsed_cmds: dict) -> list:
        risk = []
        il   = self.intent.lower()
        for acl in analysis.get("acls", []):
            if acl["acl_name"].lower() in il and re.search(r'no\s+ip\s+access|delete|remove', il):
                risk.append(f"WARNING: ACL {acl['acl_name']} ({len(acl['entries'])} entries) WILL BE REMOVED")
        return risk


class RoutingAgent(DomainAgent):
    name            = "routing"
    protocol        = "routing"
    learn_object    = "routing"
    critical_show_commands = [
        "show ip route",
        "show ip route summary",
        "show ip route ospf",
        "show ip route bgp",
    ]

    def _is_intent_relevant(self) -> bool:
        return bool(re.search(
            r'route|routing|network|redistribute|default-route|static|ip\s+route|ospf|bgp|eigrp',
            self.intent.lower()))

    def _extract_analysis(self, state: dict, parsed_cmds: dict) -> dict:
        routes_raw = (state.get("vrf", {}).get("default", {})
                         .get("address_family", {}).get("ipv4", {}).get("routes", {}))
        routes = []
        proto_counts: dict = {}
        for pfx, r in routes_raw.items():
            proto   = r.get("source_protocol", "unknown")
            nh_list = r.get("next_hop", {}).get("next_hop_list", {})
            nh      = list(nh_list.values())[0] if nh_list else {}
            routes.append({
                "prefix":    pfx,
                "protocol":  proto,
                "next_hop":  nh.get("next_hop", ""),
                "interface": nh.get("outgoing_interface", ""),
                "metric":    r.get("metric", ""),
            })
            proto_counts[proto] = proto_counts.get(proto, 0) + 1
        return {"total_routes": len(routes), "by_protocol": proto_counts, "routes": routes[:40]}

    def _evaluate_risks(self, analysis: dict, parsed_cmds: dict) -> list:
        risk = []
        il   = self.intent.lower()
        ospf_routes = [r for r in analysis.get("routes", []) if r["protocol"] == "ospf"]
        bgp_routes  = [r for r in analysis.get("routes", []) if r["protocol"] == "bgp"]
        if ospf_routes and re.search(r'no\s+router\s+ospf', il):
            risk.append(f"CRITICAL: {len(ospf_routes)} OSPF-learned routes WILL BE REMOVED from table")
            for r in ospf_routes[:4]:
                risk.append(f"  ↳ {r['prefix']} via {r['next_hop']} → GONE")
        if bgp_routes and re.search(r'no\s+router\s+bgp', il):
            risk.append(f"CRITICAL: {len(bgp_routes)} BGP-learned routes WILL BE REMOVED from table")
        return risk


class CDPAgent(DomainAgent):
    name            = "cdp"
    protocol        = "cdp"
    learn_object    = "cdp"
    critical_show_commands = [
        "show cdp neighbors detail",
        "show cdp neighbors",
    ]

    def _extract_analysis(self, state: dict, parsed_cmds: dict) -> dict:
        index = state.get("index", {})
        if not index:
            index = parsed_cmds.get("show cdp neighbors detail", {}).get("index", {})
        neighbors = []
        for idx, entry in index.items():
            ip_info = entry.get("management_addresses", {}) or entry.get("entry_addresses", {})
            neighbors.append({
                "device_id":        entry.get("device_id", ""),
                "local_interface":  entry.get("local_interface", ""),
                "remote_interface": entry.get("port_id", ""),
                "platform":         entry.get("platform", ""),
                "capabilities":     entry.get("capabilities", ""),
                "ip":               list(ip_info.keys())[0] if ip_info else "",
            })
        return {"neighbor_count": len(neighbors), "neighbors": neighbors}

    def _evaluate_risks(self, analysis: dict, parsed_cmds: dict) -> list:
        return []


class VLANAgent(DomainAgent):
    name            = "vlan"
    protocol        = "vlan"
    learn_object    = "vlan"
    critical_show_commands = [
        "show vlan brief",
        "show vlan",
        "show interfaces trunk",
    ]

    def _extract_analysis(self, state: dict, parsed_cmds: dict) -> dict:
        vlans = []
        for vid, vd in (state.get("vlans", {}) if isinstance(state, dict) else {}).items():
            vlans.append({
                "vlan_id":    vid,
                "name":       vd.get("name", ""),
                "state":      vd.get("state", "active"),
                "interfaces": list(vd.get("interfaces", {}).keys()),
            })
        return {"vlan_count": len(vlans), "vlans": vlans}

    def _evaluate_risks(self, analysis: dict, parsed_cmds: dict) -> list:
        risk = []
        il   = self.intent.lower()
        for v in analysis.get("vlans", []):
            if str(v["vlan_id"]) in il and re.search(r'no\s+vlan|shutdown|delete', il):
                risk.append(
                    f"WARNING: VLAN {v['vlan_id']} ({v['name']}) "
                    f"on {len(v['interfaces'])} interface(s) → IMPACT"
                )
        return risk


# ── Agent registry ─────────────────────────────────────────────────────────────
DOMAIN_AGENT_CLASSES = {
    "ospf":      OSPFAgent,
    "bgp":       BGPAgent,
    "interface": InterfaceAgent,
    "acl":       ACLAgent,
    "routing":   RoutingAgent,
    "cdp":       CDPAgent,
    "vlan":      VLANAgent,
}


def run_domain_expert_agents(mcp: MCPExecutionEngine, intent: str,
                              logs: list, selected_agents: list = None) -> dict:
    """
    Dispatch selected domain expert agents via MCP.
    Each agent:
      1. Calls mcp.learn_feature_state() → Genie Learn → structured JSON
      2. Calls mcp.run_show_and_parse()  → Netmiko → Genie parse → structured JSON
      3. Never sees raw CLI — only structured data
      4. Returns structured risk analysis to Supervisor Agent
    """
    agents_to_run = selected_agents or list(DOMAIN_AGENT_CLASSES.keys())
    results       = {}
    for name in agents_to_run:
        cls = DOMAIN_AGENT_CLASSES.get(name)
        if not cls:
            continue
        try:
            agent  = cls(mcp, intent, logs)
            result = agent.run()
            results[name] = result
            logs.append(
                f"[AGENT:{name.upper()}] Complete — "
                f"risks={result['risk_count']} source={result['mcp_source']}"
            )
        except Exception as e:
            logs.append(f"[AGENT:{name.upper()}] Error: {str(e)[:80]}")
            results[name] = {
                "agent": name, "error": str(e)[:100],
                "risk_indicators": [], "risk_count": 0,
                "mcp_tools_called": [], "mcp_source": "error",
            }
    return results


def _select_agents_for_intent(intent: str, llm_enriched: dict = None) -> list:
    """
    Supervisor Agent intelligence: map intent to affected protocol domains.
    Uses LLM-enriched domain list when available, falls back to regex matching.
    Returns ordered list of agent names to activate.

    Args:
        intent: raw change intent string
        llm_enriched: dict from LLM intent analysis containing 'domains' key
    """
    il     = intent.lower()

    # ── If LLM already identified domains, use them (highest accuracy) ──────
    if llm_enriched and isinstance(llm_enriched, dict):
        llm_domains = [d.lower() for d in llm_enriched.get("domains", [])
                       if d.lower() in DOMAIN_AGENT_CLASSES]
        if llm_domains:
            # Always ensure routing+interface are included
            for required in ("routing", "interface"):
                if required not in llm_domains:
                    llm_domains.insert(0, required)
            return list(dict.fromkeys(llm_domains))

    # ── Regex fallback (no LLM data yet) ────────────────────────────────────
    agents = ["routing", "interface"]   # always run

    if re.search(r'ospf|router\s+ospf|network.*area|area\s+\d|passive.*ospf', il):
        agents.append("ospf")
    if re.search(r'bgp|router\s+bgp|neighbor.*remote-as|as-path|community', il):
        agents.append("bgp")
    if re.search(r'access-list|access-group|permit|deny|ip\s+access', il):
        agents.append("acl")
    if re.search(r'vlan|switchport|trunk|access\s+vlan', il):
        agents.append("vlan")
    if re.search(r'cdp|neighbors|adjacen|topology', il):
        agents.append("cdp")

    # Destructive: remove whole routing process → run everything
    if re.search(r'no\s+router\s+ospf|no\s+router\s+bgp|no\s+router\s+eigrp', il):
        agents = list(DOMAIN_AGENT_CLASSES.keys())

    return list(dict.fromkeys(agents))  # deduplicate, preserve order


def _llm_analyze_intent(intent: str, provider: str, logs: list) -> dict:
    """
    Phase 0: LLM analyzes the change intent to determine:
    - Affected protocol domains
    - Risk level estimate
    - Key concerns to investigate
    - Agent selection

    This is the FIRST LLM call — Claude/Ollama understands the intent BEFORE
    agents collect any data. This drives domain agent selection.

    Returns: {domains, risk_estimate, concerns, agent_reasoning}
    """
    logs.append(f"[LLM:intent_analysis] Analyzing change intent via {provider}...")
    prompt = f"""You are a CCIE-level network automation expert performing pre-change analysis.

CHANGE INTENT (CLI commands to apply):
{intent}

Analyze this intent and identify exactly which network protocol domains will be affected.
Output ONLY valid JSON:
{{
  "domains": ["ospf", "bgp", "interface", "routing", "acl", "vlan", "cdp"],
  "destructive": true,
  "risk_estimate": "LOW|MEDIUM|HIGH|CRITICAL",
  "primary_protocol": "ospf",
  "concerns": ["OSPF adjacencies will drop", "Routes will be withdrawn"],
  "commands_parsed": ["no router ospf 9"],
  "agent_reasoning": "Removing OSPF process 9 will drop all OSPF adjacencies and withdraw all OSPF-learned routes from the RIB"
}}

domains must only include affected ones from: ospf, bgp, interface, routing, acl, vlan, cdp
Always include "routing" and "interface" in domains."""

    raw = call_ai(prompt, provider=provider, max_tokens=600)
    logs.append(f"[LLM:intent_analysis] Raw response: {raw[:150]}...")
    try:
        m = re.search(r'\{.*\}', raw, re.S)
        parsed = json.loads(m.group() if m else raw)
        logs.append(f"[LLM:intent_analysis] Domains identified: {parsed.get('domains', [])}")
        logs.append(f"[LLM:intent_analysis] Risk estimate: {parsed.get('risk_estimate', 'UNKNOWN')}")
        return parsed
    except Exception as e:
        logs.append(f"[LLM:intent_analysis] JSON parse failed: {e} — using regex fallback")
        return {}


# ══════════════════════════════════════════════════════════════════════════════
# ANOMALY DETECTION
# ══════════════════════════════════════════════════════════════════════════════
def detect_anomalies(raw, intent, provider, logs, intent_mode=False):
    """
    Comprehensive anomaly detection across:
    routing protocol config, ACL, route-maps, security, missing config,
    redundancy, policy consistency, and (if intent_mode) intent-specific issues.
    """
    logs.append(f"[ANOMALY] Detection starting (intent_mode={intent_mode})...")

    running_config = raw.get("running_config", "")
    routes = (raw.get("routing", {}).get("vrf", {}).get("default", {})
                 .get("address_family", {}).get("ipv4", {}).get("routes", {}))
    iface_data = raw.get("interface", {}).get("info", {})

    # Build context for LLM
    ospf_summary = {}
    for inst in raw.get("ospf", {}).values():
        if isinstance(inst, dict):
            for vrf in inst.get("vrf", {}).values():
                for area_id, area in vrf.get("area", {}).items():
                    ospf_summary[area_id] = list(area.get("interface", {}).keys())

    bgp_nbrs = []
    bgp_learn = raw.get("bgp", {})
    for inst in bgp_learn.get("instance", {}).values():
        for vrf in inst.get("vrf", {}).values():
            bgp_nbrs.extend(list(vrf.get("neighbor", {}).keys()))

    up_ifaces = [k for k, v in iface_data.items() if v.get("oper_status") == "up"]
    down_ifaces = [k for k, v in iface_data.items() if v.get("oper_status") != "up"]

    anomaly_prompt = f"""You are a senior Network Security and Configuration Auditor for Cisco IOS.
Perform a COMPREHENSIVE ANOMALY DETECTION analysis.

{'=== INTENT CONTEXT ===' if intent_mode else '=== ON-DEMAND AUDIT ==='}
{f'Operator Intent: {intent}' if intent_mode and intent else 'Standalone config audit — no specific intent.'}

=== DEVICE STATE ===
Up Interfaces: {up_ifaces}
Down Interfaces: {down_ifaces}
OSPF Areas/Interfaces: {ospf_summary}
BGP Neighbors: {bgp_nbrs}
Route counts: OSPF={sum(1 for r in routes.values() if r.get('source_protocol')=='ospf')}, Static={sum(1 for r in routes.values() if r.get('source_protocol')=='static')}

=== RUNNING CONFIGURATION ===
{running_config[:6000] if running_config else 'Not available'}

=== DETECT ALL OF THE FOLLOWING ===
1. ROUTING_PROTOCOL: Misconfigurations, passive interface issues, area mismatches, timer inconsistencies, missing authentication, suboptimal redistribution
2. ACL: Redundant rules, shadowed rules, overly permissive rules (permit any any), missing implicit deny logging, wrong order
3. ROUTE_MAP: Missing match conditions, incomplete set actions, route-maps applied but not configured, dangling references
4. SECURITY: Missing passwords, telnet instead of SSH, weak authentication, VTY access issues, missing service password-encryption, no exec timeout
5. MISSING_CONFIG: Missing loopback for router-ID, missing OSPF authentication, no logging configured, missing NTP, no SNMP community
6. REDUNDANCY: Single points of failure, no backup routes, missing default route, asymmetric routing risks
7. POLICY: Route-map vs prefix-list inconsistency, missing neighbor soft-reconfiguration, policy gaps
8. INTENT_SPECIFIC: {f'Issues specific to the intent: {intent}' if intent_mode and intent else 'N/A — standalone audit'}

For EACH anomaly found, output:
ANOMALY: [CATEGORY] [SEVERITY:CRITICAL/HIGH/MEDIUM/LOW] [TITLE]
DESCRIPTION: [what is wrong]
EVIDENCE: [specific config line or state that shows the problem]
FIX: [exact CLI to remediate]
---

After all anomalies, output:
ANOMALY_SUMMARY: [total count] anomalies found — [CRITICAL: N] [HIGH: N] [MEDIUM: N] [LOW: N]"""

    anomaly_system = (
        "You are a senior network security and operations engineer. You detect anomalies in network "
        "device configurations. Output ONLY the structured anomaly blocks as specified. "
        "Cite specific lines from the running-config as evidence."
    )
    response = call_ai(anomaly_prompt, provider, system=anomaly_system)
    logs.append("[ANOMALY] Analysis complete.")

    # Parse anomaly blocks
    anomalies = []
    blocks = re.split(r'\n---\n', response)
    for block in blocks:
        if "ANOMALY:" not in block:
            continue
        m_head = re.search(r'ANOMALY:\s*\[([^\]]+)\]\s*\[SEVERITY:([^\]]+)\]\s*(.+)', block)
        m_desc = re.search(r'DESCRIPTION:\s*(.+?)(?=\nEVIDENCE:|$)', block, re.S)
        m_evid = re.search(r'EVIDENCE:\s*(.+?)(?=\nFIX:|$)', block, re.S)
        m_fix  = re.search(r'FIX:\s*(.+?)$', block, re.S)
        if m_head:
            anomalies.append({
                "category": m_head.group(1).strip(),
                "severity": m_head.group(2).strip(),
                "title": m_head.group(3).strip(),
                "description": m_desc.group(1).strip() if m_desc else "",
                "evidence": m_evid.group(1).strip() if m_evid else "",
                "fix": m_fix.group(1).strip() if m_fix else "",
            })

    # Parse summary line
    summary_match = re.search(r'ANOMALY_SUMMARY:\s*(.+)', response)
    summary = summary_match.group(1).strip() if summary_match else f"{len(anomalies)} anomalies detected"

    severity_counts = {}
    for a in anomalies:
        sev = a.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "anomalies": anomalies,
        "summary": summary,
        "severity_counts": severity_counts,
        "total": len(anomalies),
        "intent_mode": intent_mode,
        "raw_response": response,
    }


# ══════════════════════════════════════════════════════════════════════════════
# CHAT / Q&A
# ══════════════════════════════════════════════════════════════════════════════
def answer_chat(question, context, provider, logs):
    """
    Answer a follow-up question using CCIE-grade expertise.
    Fully protocol-agnostic: uses full pipeline context including all protocol state.
    """
    logs.append(f"[CHAT] Question: {question[:100]}")

    decision_text  = context.get("decision", "")[:1000]
    classification = context.get("classification", {})
    blast          = context.get("blast_radius", {})
    validation     = context.get("validation", {})
    topology       = context.get("topology", {})
    inventory      = context.get("inventory", {})

    crit_nodes = [n["id"] for n in sorted(
                      topology.get("nodes", []),
                      key=lambda x: x.get("criticality", 0), reverse=True
                  )[:5]]

    # Build protocol-agnostic session/neighbor summary from context
    protocols_ctx = inventory.get("protocols", {}) if inventory else {}
    ospf_nbrs = protocols_ctx.get("ospf", {}).get("neighbors", [])
    bgp_nbrs  = protocols_ctx.get("bgp", {}).get("neighbors", [])
    active_ospf = [n for n in ospf_nbrs if "FULL" in str(n.get("state","")).upper() or "2WAY" in str(n.get("state","")).upper()]
    active_bgp  = [b for b in bgp_nbrs  if re.search(r"Establ|ESTABL", str(b.get("state","")))]

    # Build context summary for LLM
    session_summary = []
    if active_ospf:
        session_summary.append(f"OSPF: {len(active_ospf)} active adjacencies: " +
                               ", ".join(f"{n['neighbor_id']}({n.get('state','')} on {n.get('interface','')})"
                                         for n in active_ospf[:4]))
    if active_bgp:
        session_summary.append(f"BGP: {len(active_bgp)} established sessions: " +
                               ", ".join(f"{b['neighbor']} AS{b.get('remote_as','')}({b.get('state','')})"
                                         for b in active_bgp[:4]))
    if not session_summary:
        session_summary = ["No active OSPF/BGP sessions found in device data (offline or no protocols configured)"]

    ccie_system = (
        "You are a CCIE-certified network engineer with 10+ years of production operations experience. "
        "You answer change-impact questions with precision, citing specific IPs, neighbor IDs, "
        "interface names, route counts, and session states from the context provided. "
        "You cover ALL relevant protocols (OSPF, BGP, EIGRP, STATIC, ACL, etc.) not just one. "
        "You flag outage risks clearly and always recommend specific CLI verification steps."
    )

    prompt = f"""NETWORK CHANGE Q&A — CCIE EXPERT

=== PIPELINE ANALYSIS CONTEXT ===
Decision outcome: {decision_text[:500]}
Operation: {classification.get("operation","?")} | Protocols: {classification.get("protocols_mentioned", classification.get("protocol","?"))}
Blast radius: direct_neighbors={blast.get("directly_affected_neighbors",0)} prefixes={blast.get("directly_affected_prefixes",0)} downstream={blast.get("downstream_prefix_count",0)}
OSPF sessions at risk: {blast.get("ospf_sessions_at_risk", len(active_ospf))}
BGP sessions at risk: {blast.get("bgp_sessions_at_risk", len(active_bgp))}

Active Protocol Sessions (from Genie):
{chr(10).join(session_summary)}

Critical topology nodes: {crit_nodes}
Validation issues: {validation.get("issues", [])[:5]}
Validation warnings: {validation.get("warnings", [])[:5]}

=== USER QUESTION ===
{question[:500]}

Answer as a CCIE expert. You must:
1. Reference specific IPs, interface names, neighbor IDs from the context above
2. Cover all affected protocols, not just one
3. Recommend specific verification CLI commands (show ip ospf neighbor, show bgp summary, show ip route, show interfaces status, etc.)
4. Be explicit about what WILL break and what blast radius applies
5. Max 4 paragraphs."""

    response = call_ai(prompt, provider, system=ccie_system)
    logs.append("[CHAT] Answer generated.")
    return response


# ══════════════════════════════════════════════════════════════════════════════
# API ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/discover', methods=['POST'])
def discover():
    """
    Standalone discovery: collect + extract inventory + build topology.
    Saves to SAVED_INVENTORY[port] for reuse in /analyze.
    """
    data = request.json
    port = data.get('port', 5017)
    logs = [f"[DISCOVER] Starting discovery for port {port}..."]

    try:
        raw = collect_device(port, logs)
        inv = extract_inventory(raw, logs)
        topo, crit = stage_igraph_analysis(raw, logs)

        # Get local node for physical topology
        loopback_ips = []
        iface_ips = []
        for iname, det in raw.get("interface", {}).get("info", {}).items():
            if det.get("oper_status") != "up":
                continue
            for ip_b in det.get("ipv4", {}).keys():
                ip, plen = (ip_b.split("/") + ["32"])[:2]
                if "loopback" in iname.lower() or plen == "32":
                    loopback_ips.append(ip)
                else:
                    iface_ips.append(ip)
        local_node = sorted(loopback_ips)[0] if loopback_ips else (sorted(iface_ips)[0] if iface_ips else "router")

        phys_topo = build_topology(inv, raw, local_node, logs)

        # Save to in-memory store AND disk
        _save_inventory(str(port), {
            "raw_twin": raw, "inventory": inv,
            "topology": topo, "critical_nodes": crit,
            "physical_topology": phys_topo, "local_node": local_node,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        })

        logs.append(f"[DISCOVER] Done. Inventory saved for port {port}.")
        return jsonify({
            "inventory": inv, "topology": topo,
            "physical_topology": phys_topo, "critical_nodes": crit,
            "logs": logs, "port": port,
            "timestamp": SAVED_INVENTORY[str(port)]["timestamp"],
        })

    except Exception as e:
        tb = traceback.format_exc()
        logs.append(f"[FATAL] {str(e)}")
        return jsonify({"error": str(e), "traceback": tb, "logs": logs}), 500


@app.route('/analyze', methods=['POST'])
def orchestrate():
    """
    Main analysis pipeline. Uses saved inventory if available (skips Stage 1).
    ALWAYS uses Claude for all LLM calls (pipeline + decision).
    On-demand operations (discover, simulate, anomalies, healing) use Ollama instead.
    """
    data = request.json
    port = data.get('port', 5017)
    intent = data.get('intent', '')
    use_saved = data.get('use_saved_inventory', True)
    pipeline_provider = _resolve_provider(data.get("provider"))
    logs = [f"[INIT] Pipeline | provider={pipeline_provider} | port={port}"]

    try:
        saved = SAVED_INVENTORY.get(str(port))

        if use_saved and saved:
            logs.append(f"[STAGE 1] Using saved inventory from {saved['timestamp']} (skipping collection).")
            raw_twin = saved["raw_twin"]
            planned_cmds = ["(from saved inventory)"]
            topology = saved["topology"]
            critical_nodes = saved["critical_nodes"]
            physical_topology = saved["physical_topology"]
            inventory = saved["inventory"]
        else:
            logs.append("[STAGE 1] No saved inventory — collecting from device...")
            raw_twin, planned_cmds = collect_device(port, logs), []
            if intent:
                plan_prompt = (f"Network change intent: '{intent}'.\n"
                               f"List exactly 4 Cisco IOS 'show' commands to assess state before this change.\n"
                               f"Return ONLY a comma-separated list, nothing else.")
                cmds_raw = call_ai(plan_prompt, pipeline_provider)
                planned_cmds = re.findall(r'show\s+[\w\-\s\/\.]+', cmds_raw, re.I)[:4]

            topology, critical_nodes = stage_igraph_analysis(raw_twin, logs)
            inventory = extract_inventory(raw_twin, logs)
            local_node = topology.get("nodes", [{}])[0].get("id", "router") if topology.get("nodes") else "router"
            physical_topology = build_topology(inventory, raw_twin, local_node, logs)

        # ── Domain Expert Agent analysis via MCP ─────────────────────────────
        # Run agents ONCE before the decision loop (they collect live device data
        # which doesn't change between rounds — no need to re-run per round)
        _mcp_for_analyze = MCPExecutionEngine(port, logs)
        _mcp_for_analyze.build_testbed(channel="all")
        selected_agents_for_analyze = _select_agents_for_intent(intent)
        agent_results = run_domain_expert_agents(_mcp_for_analyze, intent, logs, selected_agents_for_analyze)
        all_risk_indicators = []
        for agt_r in agent_results.values():
            all_risk_indicators.extend(agt_r.get("risk_indicators", []))
        if all_risk_indicators:
            logs.append(f"[AGENTS] Total risk indicators: {len(all_risk_indicators)}")
        try: _mcp_for_analyze.disconnect()
        except: pass

        # ── Dynamic Decision Loop: Stage 3 ↔ Stage 5 (closed feedback loop) ──────
        # Round 1: Generate config → Stage 5 assesses → if NO-GO, extract reasons
        # Round 2: Stage 3 re-generates safer config using Stage 5 reasons → Stage 5 re-assesses
        #
        # This is the "dynamically learning based on LLM feedback" architecture:
        # the LLM's own NO-GO verdict + reasons feed back as constraints for healing.
        #
        # Claude: 2 rounds (fast API calls allow it)
        # Ollama: 1 round (Stage 3 already has its own 3-iteration internal loop;
        #         adding outer loop would exceed 10-min timeout for local models)
        max_rounds = 2 if pipeline_provider == 'claude' else 1
        stage5_feedback = []   # NO-GO reasons from Stage 5 → constraints for Stage 3
        healed_config, audit_trail, validation, decision_result = None, [], {}, None

        for _round in range(1, max_rounds + 1):
            logs.append(
                f"[DECISION LOOP] Round {_round}/{max_rounds}" +
                (f" — incorporating {len(stage5_feedback)} Stage 5 constraints" if stage5_feedback else "")
            )

            # Stage 3: Generate (or re-generate with Stage 5 feedback)
            healed_config, audit_trail = stage_recursive_healing(
                intent, topology, critical_nodes, pipeline_provider, logs,
                stage5_feedback=stage5_feedback,
            )
            # Stage 4: Validate against live device state
            validation = stage_variable_validation(healed_config, raw_twin, topology, logs)

            # Stage 5: LLM impact assessment (Pass 1 initial + Pass 2 self-critique)
            decision_result = stage_llm_decision(
                intent, healed_config, raw_twin, topology, validation,
                audit_trail, pipeline_provider, logs,
                agent_risk_indicators=all_risk_indicators,
                agent_results=agent_results,
                round_num=_round,
            )

            # Extract verdict for loop control
            _verdict = ''
            for _dl in decision_result["raw"].replace('**', '').split('\n'):
                if _dl.strip().startswith('DECISION:'):
                    _verdict = _dl.split(':', 1)[-1].strip().upper()
                    break
            logs.append(f"[DECISION LOOP] Round {_round}: verdict='{_verdict}'")

            if _verdict in ('GO', 'PROCEED WITH CAUTION') or _round >= max_rounds:
                break  # Accepted verdict or exhausted rounds — use this result

            # Extract Stage 5 NO-GO blocking reasons as feedback for Stage 3 Round 2
            stage5_feedback = []
            for _dl in decision_result["raw"].replace('**', '').split('\n'):
                _ls = _dl.strip()
                if _ls and any(k in _ls.upper() for k in
                               ('IMPACTED', 'BLOCKED', 'CRITICAL', 'DISRUPT', 'NO-GO', 'AT RISK')):
                    stage5_feedback.append(_ls[:120])
            stage5_feedback = stage5_feedback[:6]

            if not stage5_feedback:
                logs.append("[DECISION LOOP] No actionable Stage 5 feedback — stopping loop.")
                break
            logs.append(f"[DECISION LOOP] Feeding {len(stage5_feedback)} NO-GO reasons to Stage 3 Round 2...")

        logs.append("[DONE] All stages complete.")

        result = {
            "decision": decision_result["raw"],
            "classification": decision_result["classification"],
            "blast_radius": decision_result["blast_radius"],
            "healed_config": healed_config,
            "topology": topology,
            "physical_topology": physical_topology,
            "critical_nodes": critical_nodes,
            "validation": validation,
            "audit_trail": audit_trail,
            "digital_twin": raw_twin,
            "planned_cmds": planned_cmds,
            "inventory": inventory,  # full inventory included — chat uses protocols section
            "agent_results": agent_results,
            "agent_risk_indicators": all_risk_indicators,
            "used_saved_inventory": use_saved and saved is not None,
            "logs": logs,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        # Save pipeline result to disk
        _save_to_disk(f"pipeline_port_{port}", result)

        return jsonify(result)

    except Exception as e:
        tb = traceback.format_exc()
        logs.append(f"[FATAL] {str(e)}")
        return jsonify({"error": str(e), "traceback": tb, "logs": logs}), 500


@app.route('/simulate', methods=['POST'])
def simulate():
    """
    Config Simulation — LLM + Genie Diff hybrid.

    Flow:
      1. LLM analyzes intent → predicts state changes (Claude/Ollama)
      2. MCP takes PRE-snapshot via Genie Learn (if live device available)
      3. LLM predictions applied to PRE state → simulated POST state
      4. Genie Diff(PRE, POST) → deterministic structural diff
      5. LLM text simulation — added/removed lines, modified sections
      6. Combined result returned to GUI

    If no live device: LLM-only simulation using saved inventory.
    """
    data = request.json
    port = data.get('port', 5017)
    intent = data.get('intent', '')
    use_genie_diff = data.get('genie_diff', True)   # NEW: enable Genie Diff by default
    sim_provider = _resolve_provider(data.get('provider'))
    diff_features = data.get('features', ['interface', 'routing', 'ospf', 'bgp', 'acl'])
    logs = [f"[SIM] Simulation request for port {port} [genie_diff={use_genie_diff}] [{sim_provider}]"]

    try:
        saved = SAVED_INVENTORY.get(str(port))
        if saved:
            raw = saved["raw_twin"]
            logs.append("[SIM] Using saved inventory.")
        else:
            logs.append("[SIM] No saved inventory — collecting...")
            raw = collect_device(port, logs)

        # ── Mode 1: Genie Diff via MCP (non-blocking, LLM-predicted post state) ─
        genie_diff_result = None
        if use_genie_diff:
            logs.append("[SIM:MCP] Genie Diff simulation via MCP engine...")
            _mcp_sim = MCPExecutionEngine(port, logs)
            try:
                tb_sim       = _mcp_sim.build_testbed(channel="all")
                sim_channels = tb_sim.get("channels", [])
                logs.append(f"[SIM:MCP] Testbed: channels={sim_channels}")

                if sim_channels:
                    # Step 1: LLM predicts state changes (Claude/Ollama)
                    logs.append(f"[SIM:LLM] {sim_provider} predicting post-change state...")
                    post_state_prompt = (
                        f"You are simulating Cisco IOS state changes.\n"
                        f"Intent to apply:\n{intent}\n\n"
                        f"Predict protocol state changes. Answer ONLY in JSON:\n"
                        '{{"ospf_neighbors_drop":[],"routes_removed":[],"interfaces_down":[]}}'
                    )
                    predicted = call_ai(post_state_prompt, sim_provider, max_tokens=300)
                    logs.append(f"[SIM:LLM] Prediction: {predicted[:80]}...")

                    # Step 2: MCP PRE snapshot via Genie Learn API
                    pre_snap_result   = _mcp_sim.take_snapshot("pre", diff_features)
                    captured_features = [k for k, v in pre_snap_result.get("features", {}).items()
                                         if v.get("status") == "captured"]
                    logs.append(f"[SIM:MCP] PRE snapshot: {captured_features}")

                    # Step 3: Apply LLM predictions → simulated POST state, then Genie Diff
                    genie_diff_per_feat = {}
                    for feat in captured_features:
                        pre_key  = _snapshot_key(port, "pre", feat)
                        pre_data = STATE_SNAPSHOTS.get(pre_key, {})
                        if pre_data:
                            post_data = _apply_predicted_changes_to_state(pre_data, feat, intent, predicted)
                            STATE_SNAPSHOTS[_snapshot_key(port, "post", feat)] = post_data
                            diff = _mcp_sim.compare_snapshots(feat, "pre", "post")
                            genie_diff_per_feat[feat] = diff
                            counts = diff.get("counts", {})
                            logs.append(
                                f"[SIM:GENIE] '{feat}': "
                                f"+{counts.get('added',0)} -{counts.get('removed',0)} "
                                f"~{counts.get('modified',0)} [{diff.get('engine','?')}]"
                            )
                    genie_diff_result = genie_diff_per_feat or None
                else:
                    logs.append("[SIM:MCP] No live connection — LLM simulation only")
            except Exception as e:
                logs.append(f"[SIM:MCP] Genie Diff error: {str(e)[:100]}")
            finally:
                try: _mcp_sim.disconnect()
                except: pass

        # ── Mode 2: LLM text simulation (fallback or explicit) ──────────────
        llm_result = simulate_config(intent, raw, sim_provider, logs)

        # Merge LLM simulation + Genie Diff results
        result = llm_result if isinstance(llm_result, dict) else {}
        result["genie_diff"] = genie_diff_result       # dict of {feature: diff} or None
        result["genie_diff_available"] = genie_diff_result is not None
        # Flatten Genie Diff summary for UI
        if genie_diff_result:
            result["genie_summary"] = {
                feat: {
                    "added":    len(d.get("added",[])),
                    "removed":  len(d.get("removed",[])),
                    "modified": len(d.get("modified",[])),
                    "verdict":  d.get("risk",{}).get("verdict","UNKNOWN"),
                    "engine":   d.get("engine","unknown"),
                }
                for feat, d in genie_diff_result.items()
            }
        result["provider"] = sim_provider
        result["logs"] = logs
        result["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")

        _save_to_disk(f"simulate_port_{port}", result)
        return jsonify(result)

    except Exception as e:
        logs.append(f"[FATAL] {str(e)}")
        return jsonify({"error": str(e), "logs": logs}), 500


def _apply_predicted_changes_to_state(pre_data: dict, feature: str, intent: str, predicted_str: str) -> dict:
    """
    Apply predicted intent changes to pre-state to create a simulated post-state.
    Used for dry-run Genie Diff simulation.
    Fully protocol-agnostic: uses LLM predictions + generic intent parsing.
    No hardcoded OSPF/BGP-specific logic — all protocol reasoning lives in the LLM.
    """
    import copy
    post_data = copy.deepcopy(pre_data)
    il = intent.lower()

    # Parse LLM prediction (generic — LLM provides protocol-aware drop/shutdown lists)
    try:
        pred = json.loads(re.search(r'\{.*\}', predicted_str, re.S).group())
    except Exception:
        pred = {}

    # ── Generic: any routing process removal → clear that protocol's neighbor/route state
    # Detect "no router <proto> <pid>" pattern and clear neighbor tables for that proto
    removed_processes = re.findall(r'no\s+router\s+(\w+)(?:\s+(\d+))?', il)
    for proto, pid in removed_processes:
        if feature == proto:
            # Generic: clear all neighbor/session state for this protocol feature
            _clear_protocol_state_recursive(post_data)

    # ── Generic: LLM-predicted drops (any protocol — LLM fills these fields)
    for nbr_drop in pred.get("neighbors_drop", pred.get("ospf_neighbors_drop", [])):
        _remove_neighbor_recursive(post_data, nbr_drop)

    # ── Generic: routing table — remove routes for any removed protocol
    if feature == "routing":
        routes = (post_data.get("vrf", {}).get("default", {})
                  .get("address_family", {}).get("ipv4", {}).get("routes", {}))
        for proto, _ in removed_processes:
            to_remove = [p for p, r in routes.items() if r.get("source_protocol") == proto]
            for p in to_remove:
                routes.pop(p, None)
        # LLM-predicted routes to remove
        for pfx in pred.get("routes_removed", []):
            routes.pop(pfx, None)

    # ── Generic: interface shutdown (matches any interface name in intent)
    if feature == "interface":
        shutdown_ifaces = re.findall(r'interface\s+(\S+)', il)
        for iface_name, iface_d in post_data.get("info", {}).items():
            iname_norm = iface_name.lower().replace("/", "").replace(".", "")
            for target in shutdown_ifaces:
                target_norm = target.lower().replace("/", "").replace(".", "")
                if target_norm in iname_norm or iname_norm in target_norm:
                    if "shutdown" in il:
                        iface_d["oper_status"] = "down"
                        iface_d["enabled"] = False
        # LLM-predicted interface downs
        for iface_down in pred.get("interfaces_down", []):
            for iface_name, iface_d in post_data.get("info", {}).items():
                if iface_down.lower() in iface_name.lower():
                    iface_d["oper_status"] = "down"
                    iface_d["enabled"] = False

    return post_data


def _clear_protocol_state_recursive(data: dict, depth: int = 0):
    """Recursively clear neighbor/session dicts from any protocol state dict."""
    if depth > 8 or not isinstance(data, dict):
        return
    for k, v in data.items():
        if k in ("neighbor", "neighbors", "sessions", "peers") and isinstance(v, dict):
            v.clear()
        elif isinstance(v, dict):
            _clear_protocol_state_recursive(v, depth + 1)


def _remove_neighbor_recursive(data: dict, nbr_id: str, depth: int = 0):
    """Recursively remove a specific neighbor ID from any protocol state dict."""
    if depth > 8 or not isinstance(data, dict):
        return
    for k, v in data.items():
        if k in ("neighbor", "neighbors", "sessions", "peers") and isinstance(v, dict):
            v.pop(nbr_id, None)
        elif isinstance(v, dict):
            _remove_neighbor_recursive(v, nbr_id, depth + 1)


@app.route('/genie_diff', methods=['POST'])
def genie_diff_endpoint():
    """
    Run a real Genie Diff between pre and post snapshots.
    Requires pre/post snapshots to exist in STATE_SNAPSHOTS.
    Use /take_snapshot first to capture state.
    """
    data = request.json
    port = data.get('port', 5017)
    features = data.get('features', ['ospf', 'bgp', 'routing', 'interface'])
    logs = [f"[GENIE_DIFF] Request port={port} features={features}"]

    try:
        result = genie_diff_features(port, features, logs)
        return jsonify({
            "diff": result,
            "features": features,
            "snapshot_keys": {f: {
                "pre":  _snapshot_key(port, "pre",  f),
                "post": _snapshot_key(port, "post", f),
                "pre_available":  _snapshot_key(port, "pre",  f) in STATE_SNAPSHOTS,
                "post_available": _snapshot_key(port, "post", f) in STATE_SNAPSHOTS,
            } for f in features},
            "logs": logs,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
    except Exception as e:
        return jsonify({"error": str(e), "logs": logs}), 500


@app.route('/take_snapshot', methods=['POST'])
def take_snapshot_endpoint():
    """
    Connect to device and take a named state snapshot (pre or post).
    Stores results in STATE_SNAPSHOTS for use with /genie_diff.
    """
    data = request.json
    port = data.get('port', 5017)
    label = data.get('label', 'pre')   # 'pre' or 'post'
    features = data.get('features', ['interface', 'routing', 'ospf', 'bgp', 'acl'])
    logs = [f"[SNAPSHOT] Taking {label} snapshot for port {port}..."]

    if not PYATS_AVAILABLE:
        # Store mock data
        for feat in features:
            STATE_SNAPSHOTS[_snapshot_key(port, label, feat)] = {}
        return jsonify({"status": "mock", "label": label, "features": features, "logs": logs})

    try:
        dev = get_device_obj(port)
        dev.connect(log_stdout=False, dialog=gns3_dialog, learn_hostname=True)
        dev.execute('terminal length 0')
        summary = take_state_snapshot(port, label, features, dev, logs)
        return jsonify({
            "status": "ok", "label": label,
            "summary": summary, "features": features,
            "logs": logs, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
    except Exception as e:
        logs.append(f"[FATAL] {str(e)}")
        return jsonify({"error": str(e), "logs": logs}), 500
    finally:
        try:
            if PYATS_AVAILABLE and 'dev' in dir() and dev.is_connected():
                dev.disconnect()
        except Exception:
            pass


@app.route('/netmiko_exec', methods=['POST'])
def netmiko_exec():
    """
    Execute a CLI command via Netmiko SSH channel.
    Preferred for config push operations — cleaner than Telnet for some IOS versions.
    """
    data = request.json
    port = data.get('port', 5017)
    command = data.get('command', '')
    is_config = data.get('is_config', False)   # True = config terminal commands
    logs = [f"[NETMIKO] Port={port} cmd='{command[:60]}' config={is_config}"]

    if not NETMIKO_AVAILABLE:
        return jsonify({"error": "Netmiko not installed. pip install netmiko", "logs": logs}), 400

    try:
        nm = NETMIKO_SESSIONS.get(str(port))
        if not nm:
            nm = ConnectHandler(
                device_type="cisco_ios",
                host=WINDOWS_IP,
                port=port,
                username=GNS3_USERNAME,
                password=GNS3_PASSWORD,
                timeout=30,
            )
            NETMIKO_SESSIONS[str(port)] = nm
            logs.append("[NETMIKO] New SSH session established.")
        else:
            logs.append("[NETMIKO] Using existing SSH session.")

        if is_config:
            cmds = [c.strip() for c in command.split("\n") if c.strip()]
            output = nm.send_config_set(cmds)
        else:
            output = nm.send_command(command, read_timeout=60)

        logs.append(f"[NETMIKO] Command executed. Output: {len(output)} chars.")
        return jsonify({
            "output": output,
            "command": command,
            "channel": "ssh_netmiko",
            "logs": logs,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
    except Exception as e:
        logs.append(f"[FATAL] {str(e)}")
        return jsonify({"error": str(e), "logs": logs}), 500


@app.route('/mcp_pipeline', methods=['POST'])
def mcp_pipeline():
    """
    ENTERPRISE-GRADE Network Change Orchestration Pipeline
    ═══════════════════════════════════════════════════════

    Full 8-phase architecture (per spec):

    Phase 0: LLM Intent Analysis
      User Intent → Claude/Ollama → identify affected domains, risk estimate,
      concerns, agent_reasoning → drives agent selection

    Phase 1: Supervisor Agent — domain selection
      LLM output + regex → selected domain agents

    Phase 2: MCP Testbed
      build_testbed → Netmiko SSH + pyATS Telnet sessions to device

    Phase 3: MCP PRE-Snapshot
      take_snapshot("pre") → Genie Learn API → full protocol state per domain

    Phase 4: Domain Agents → MCP Tools → PyATS+Genie
      Agent never touches device. Agent calls:
        mcp.learn_feature_state()  → Genie Learn → structured JSON
        mcp.run_show_and_parse()   → Netmiko SSH → Genie Parse → structured JSON
      Agent receives ONLY structured JSON — never raw CLI

    Phase 5: Agent Risk Analysis
      Each agent correlates Genie JSON with intent → risk indicators

    Phase 6: MCP POST-Snapshot + Genie Diff
      Simulate post-state → compare_snapshots → added/removed/modified

    Phase 7: Supervisor LLM Synthesis
      Claude/Ollama receives all structured agent JSON
      → CCIE-grade verdict with specific IPs, neighbors, route counts
      → Never receives raw CLI output

    Phase 8: Result Assembly
      Full structured result for GUI
    """
    data     = request.json or {}
    port     = data.get('port', 5017)
    intent   = data.get('intent', '')
    provider = _resolve_provider(data.get('provider'))
    logs     = [
        f"[PIPELINE] Enterprise Network Change Orchestration v7",
        f"[PIPELINE] port={port} | provider={provider}",
        f"[PIPELINE] Intent: '{intent[:80]}'",
    ]

    mcp = None  # ensure teardown in finally

    try:
        if not intent.strip():
            return jsonify({"error": "Intent required", "logs": logs}), 400

        # ═══════════════════════════════════════════════════════════
        # PHASE 0: LLM Intent Analysis
        # Claude/Ollama understands the intent BEFORE any agent runs
        # ═══════════════════════════════════════════════════════════
        logs.append(f"[PHASE:0] LLM Intent Analysis — {provider} analyzing change intent...")
        intent_analysis = _llm_analyze_intent(intent, provider, logs)
        domains_identified = intent_analysis.get("domains", [])
        risk_estimate      = intent_analysis.get("risk_estimate", "UNKNOWN")
        concerns           = intent_analysis.get("concerns", [])
        agent_reasoning    = intent_analysis.get("agent_reasoning", "")
        logs.append(f"[PHASE:0] LLM identified domains: {domains_identified}")
        logs.append(f"[PHASE:0] LLM risk estimate: {risk_estimate}")
        if agent_reasoning:
            logs.append(f"[PHASE:0] LLM reasoning: {agent_reasoning[:120]}")

        # ═══════════════════════════════════════════════════════════
        # PHASE 1: Supervisor — Domain Agent Selection
        # LLM output drives selection (regex fallback if LLM fails)
        # ═══════════════════════════════════════════════════════════
        logs.append(f"[PHASE:1] Supervisor Agent — selecting domain agents...")
        selected_agents = _select_agents_for_intent(intent, intent_analysis)
        logs.append(f"[PHASE:1] Selected agents: {selected_agents}")
        logs.append(f"[PHASE:1] Agent count: {len(selected_agents)} domain experts dispatched")

        # ═══════════════════════════════════════════════════════════
        # PHASE 2: MCP Testbed
        # Establish Netmiko SSH + pyATS Telnet to device
        # ═══════════════════════════════════════════════════════════
        logs.append(f"[PHASE:2] MCP Testbed — connecting to device port={port}...")
        logs.append(f"[MCP:build_testbed] Establishing Netmiko SSH + pyATS Telnet channels...")
        mcp            = MCPExecutionEngine(port, logs)
        testbed_result = mcp.build_testbed(channel="all")
        channels       = testbed_result.get("channels", [])
        hostname       = testbed_result.get("hostname", "unknown")
        logs.append(f"[PHASE:2] Testbed ready — channels={channels} hostname={hostname}")

        # ═══════════════════════════════════════════════════════════
        # PHASE 3: MCP PRE-Snapshot via Genie Learn API
        # Capture device state BEFORE any change
        # ═══════════════════════════════════════════════════════════
        snap_features = [a for a in selected_agents if a in DOMAIN_AGENT_CLASSES][:6]
        logs.append(f"[PHASE:3] MCP PRE-Snapshot via Genie Learn API: {snap_features}")
        pre_snap  = mcp.take_snapshot("pre", snap_features)
        captured  = [k for k, v in pre_snap.get("features", {}).items() if v.get("status") == "captured"]
        logs.append(f"[PHASE:3] PRE snapshots captured: {captured}")

        # ═══════════════════════════════════════════════════════════
        # PHASE 4+5: Domain Agents → MCP → PyATS+Genie → Risk Analysis
        # Each agent calls MCP tools. MCP executes via Netmiko/Genie.
        # Agents NEVER touch device directly. Only see structured JSON.
        # ═══════════════════════════════════════════════════════════
        logs.append(f"[PHASE:4] Dispatching {len(selected_agents)} domain agents via MCP...")
        logs.append(f"[PHASE:4] Flow: Agent → MCP.learn_feature_state() → Genie Learn → JSON")
        logs.append(f"[PHASE:4] Flow: Agent → MCP.run_show_and_parse() → Netmiko SSH → Genie Parse → JSON")
        agent_results = run_domain_expert_agents(mcp, intent, logs, selected_agents)

        # ═══════════════════════════════════════════════════════════
        # Collect structured results from all agents
        # ═══════════════════════════════════════════════════════════
        all_risks       = []
        agent_summaries = {}
        mcp_tool_trace  = []

        for name, r in agent_results.items():
            risks = r.get("risk_indicators", [])
            all_risks.extend(risks)
            agent_summaries[name] = {
                "risk_count":       r.get("risk_count", 0),
                "mcp_source":       r.get("mcp_source", ""),
                "mcp_tools_called": r.get("mcp_tools_called", []),
                "relevant":         r.get("relevant_to_intent", True),
                "learn_object":     r.get("learn_object", name),
                "analysis":         {
                    k: v for k, v in r.get("analysis", {}).items()
                    if k in ("neighbor_count","full_neighbors","established",
                              "total","up","down","total_routes","by_protocol",
                              "acl_count","vlan_count","neighbor_count")
                },
                "risk_indicators": risks[:5],
            }
            mcp_tool_trace.append({
                "agent":       name,
                "tools_called": [
                    {"tool": "learn_feature_state",
                     "input": {"feature": r.get("learn_object", name)},
                     "source": r.get("mcp_source", "none"),
                     "result": f"Genie JSON: {r.get('learn_object',name)} state model"},
                    {"tool": "run_show_and_parse",
                     "input": {"commands": r.get("critical_show_commands", [])[:2]},
                     "source": r.get("mcp_source", "none"),
                     "result": "Structured parsed output"},
                ],
                "risk_count":  r.get("risk_count", 0),
                "risks":       risks[:5],
                "analysis":    r.get("analysis", {}),
            })

        logs.append(f"[PHASE:5] Agent analysis complete — total risks: {len(all_risks)}")
        critical_count = sum(1 for r in all_risks if "CRITICAL" in str(r))
        warning_count  = sum(1 for r in all_risks if "WARNING" in str(r))
        logs.append(f"[PHASE:5] CRITICAL: {critical_count} | WARNING: {warning_count}")

        # ═══════════════════════════════════════════════════════════
        # PHASE 6: Genie Diff — simulated post-state comparison
        # Uses MCP.compare_snapshots() for deterministic diff
        # ═══════════════════════════════════════════════════════════
        logs.append(f"[PHASE:6] Genie Diff — simulating post-change state...")
        genie_diff_results = {}
        for feat in snap_features[:3]:  # diff top 3 features
            try:
                # Build simulated post-state from intent
                pre_key  = _snapshot_key(port, "pre", feat)
                pre_data = STATE_SNAPSHOTS.get(pre_key, {})
                if pre_data:
                    post_data = _apply_predicted_changes_to_state(pre_data, feat, intent, "{}")
                    STATE_SNAPSHOTS[_snapshot_key(port, "post", feat)] = post_data
                    diff = mcp.compare_snapshots(feat, "pre", "post")
                    genie_diff_results[feat] = diff
                    counts = diff.get("counts", {})
                    logs.append(
                        f"[PHASE:6] Genie Diff '{feat}': "
                        f"+{counts.get('added',0)} -{counts.get('removed',0)} ~{counts.get('modified',0)}"
                    )
            except Exception as e:
                logs.append(f"[PHASE:6] Genie Diff '{feat}' failed: {str(e)[:60]}")

        # ═══════════════════════════════════════════════════════════
        # PHASE 7: Supervisor LLM Synthesis
        # Claude/Ollama synthesizes CCIE-grade verdict from agent JSON
        # NEVER receives raw CLI — only structured JSON from agents
        # ═══════════════════════════════════════════════════════════
        logs.append(f"[PHASE:7] Supervisor LLM synthesis via {provider}...")
        logs.append(f"[PHASE:7] LLM receives structured agent JSON — no raw CLI")

        # Build clean structured context for LLM
        # All data: Agent → MCP → Netmiko SSH → Genie → JSON
        supervisor_context = {
            "change_intent": intent,
            "device_port": port,
            "hostname": hostname,
            "mcp_channels": channels,
            "llm_intent_analysis": {
                "domains_identified": domains_identified,
                "risk_estimate": risk_estimate,
                "concerns": concerns,
                "agent_reasoning": agent_reasoning,
            },
            "agents_dispatched": selected_agents,
            "pre_snapshots_captured": captured,
            "genie_diff_available": len(genie_diff_results) > 0,
            "risk_summary": {
                "total": len(all_risks),
                "critical": critical_count,
                "warning": warning_count,
                "critical_indicators": [r for r in all_risks if "CRITICAL" in str(r)][:8],
                "warning_indicators":  [r for r in all_risks if "WARNING" in str(r)][:5],
            },
            "agent_findings": {
                name: {
                    "source": s.get("mcp_source"),
                    "risks": s.get("risk_indicators", []),
                    "analysis": s.get("analysis", {}),
                }
                for name, s in agent_summaries.items()
            },
            "genie_diff_summary": {
                feat: {
                    "added": len(d.get("added",[])),
                    "removed": len(d.get("removed",[])),
                    "modified": len(d.get("modified",[])),
                    "risk_verdict": d.get("risk",{}).get("verdict","UNKNOWN"),
                }
                for feat, d in genie_diff_results.items()
            },
            "data_source": "All data via MCP→Netmiko SSH→Genie structured JSON (no raw CLI)",
        }

        supervisor_prompt = f"""You are a CCIE-certified Supervisor Agent for enterprise network change impact assessment.

ARCHITECTURE: Intent → LLM Analysis → Domain Agents → MCP → Netmiko SSH → PyATS+Genie → Structured JSON → You
DATA QUALITY: All findings from Genie-parsed structured JSON. You never saw raw CLI output.

CHANGE INTENT:
{intent}

STRUCTURED CONTEXT FROM DOMAIN AGENTS (via MCP→PyATS→Genie):
{json.dumps(supervisor_context, indent=2, default=str)[:4000]}

Provide CCIE-grade impact assessment. Reference specific IPs, neighbor IDs, prefix counts from agent data.
Output ONLY valid JSON (no markdown, no preamble, no ```json):
{{
  "verdict": "SAFE|WARNING|CRITICAL|NO-GO",
  "risk_score": 0.0,
  "summary": "precise one-sentence with specific device data (IPs, neighbors, routes)",
  "findings": [
    "CRITICAL: OSPF process 9 removal will drop N FULL adjacencies (list specific neighbor IPs)",
    "WARNING: X OSPF-learned routes will be withdrawn from RIB"
  ],
  "affected_neighbors": ["10.x.x.x"],
  "affected_prefixes": ["x.x.x.x/xx"],
  "affected_agents": ["ospf","routing"],
  "recommendation": "specific actionable recommendation with rollback plan",
  "rollback_commands": ["router ospf 9", "network 9.9.0.0 0.0.0.255 area 0"],
  "ccie_analysis": "3-sentence expert analysis citing agent findings, Genie diff results, and blast radius",
  "blast_radius": "quantified impact: N neighbors, X routes, Y prefixes"
}}"""

        raw_verdict = call_ai(supervisor_prompt, provider=provider, max_tokens=1500)
        logs.append(f"[PHASE:7] Supervisor verdict received ({len(raw_verdict)} chars)")

        # Parse structured JSON from Supervisor
        verdict_parsed = {}
        try:
            clean = raw_verdict.strip()
            # Strip markdown fences
            clean = re.sub(r'^```(?:json)?\s*', '', clean, flags=re.M)
            clean = re.sub(r'```\s*$', '', clean, flags=re.M)
            clean = clean.strip()
            m = re.search(r'\{{.*?"verdict".*?\}}', clean, re.S)
            verdict_parsed = json.loads(m.group() if m else clean)
            logs.append(f"[PHASE:7] Verdict: {verdict_parsed.get('verdict')} | Risk: {verdict_parsed.get('risk_score')}")
        except Exception as parse_err:
            logs.append(f"[PHASE:7] JSON parse failed ({parse_err}) — deriving from agent data")
            # Derive from agent data if LLM JSON fails
            verdict_parsed = {{
                "verdict":     ("CRITICAL" if critical_count >= 1
                                else "WARNING" if warning_count >= 1 else "SAFE"),
                "risk_score":  min(1.0, round(critical_count * 0.5 + warning_count * 0.2, 2)),
                "summary":     f"Agent analysis: {{critical_count}} critical, {{warning_count}} warnings",
                "findings":    all_risks[:10],
                "recommendation": raw_verdict[:300] if raw_verdict else "Review agent findings",
                "rollback_commands": [],
                "ccie_analysis": agent_reasoning or "See agent findings",
                "blast_radius": f"{{critical_count}} critical issues across {{len(selected_agents)}} domains",
            }}

        # ═══════════════════════════════════════════════════════════
        # PHASE 8: Result Assembly
        # ═══════════════════════════════════════════════════════════
        logs.append(f"[PHASE:8] Assembling full result for GUI...")
        result = {{
            # Supervisor verdict
            "verdict":            verdict_parsed.get("verdict", "UNKNOWN"),
            "risk_score":         verdict_parsed.get("risk_score", 0.0),
            "summary":            verdict_parsed.get("summary", ""),
            "findings":           verdict_parsed.get("findings", all_risks[:10]),
            "affected_neighbors": verdict_parsed.get("affected_neighbors", []),
            "affected_prefixes":  verdict_parsed.get("affected_prefixes", []),
            "affected_agents":    verdict_parsed.get("affected_agents", []),
            "recommendation":     verdict_parsed.get("recommendation", ""),
            "rollback_commands":  verdict_parsed.get("rollback_commands", []),
            "ccie_analysis":      verdict_parsed.get("ccie_analysis", ""),
            "blast_radius":       verdict_parsed.get("blast_radius", ""),

            # LLM Intent Analysis (Phase 0)
            "intent_analysis":    intent_analysis,
            "domains_identified": domains_identified,
            "risk_estimate":      risk_estimate,
            "concerns":           concerns,
            "agent_reasoning":    agent_reasoning,

            # MCP execution trace
            "mcp_testbed":        testbed_result,
            "mcp_channels":       channels,
            "mcp_tool_trace":     mcp_tool_trace,
            "pre_snapshots":      pre_snap,
            "genie_diff":         genie_diff_results,

            # Domain agent results
            "agent_results":         agent_results,
            "selected_agents":       selected_agents,
            "agent_summaries":       agent_summaries,
            "agent_risk_indicators": all_risks,

            # Pipeline metadata
            "provider":    provider,
            "raw_verdict": raw_verdict,
            "logs":        logs,
            "timestamp":   time.strftime("%Y-%m-%d %H:%M:%S"),
        }}

        _save_to_disk(f"mcp_pipeline_port_{{port}}", result)
        return jsonify(result)

    except Exception as e:
        tb  = traceback.format_exc()
        msg = str(e)
        logs.append(f"[FATAL] {{msg}}")
        short_tb = "\n".join(tb.split("\n")[-12:])
        return jsonify({{"error": msg, "traceback": short_tb, "logs": logs}}), 500

    finally:
        # Always clean up MCP connections
        if mcp:
            try:
                mcp.disconnect()
            except Exception:
                pass

@app.route('/agent_analysis', methods=['POST'])
def agent_analysis():
    """
    Standalone Domain Expert Agent Analysis via MCP.
    Agents call MCP tools — not raw device access.
    POST: {port, intent, agents: [optional list]}
    Returns: {agents, all_risk_indicators, mcp_testbed, command_map, logs}
    """
    data     = request.json or {}
    port     = data.get('port', 5017)
    intent   = data.get('intent', '')
    selected = data.get('agents', None)
    provider = _resolve_provider(data.get('provider'))
    logs     = [f"[AGENT_ANALYSIS] port={port} intent='{intent[:50]}' provider={provider}"]

    try:
        agents_to_run = selected or _select_agents_for_intent(intent) or list(DOMAIN_AGENT_CLASSES.keys())
        logs.append(f"[AGENT_ANALYSIS] Selected agents: {agents_to_run}")

        # Build MCP engine
        mcp        = MCPExecutionEngine(port, logs)
        tb_result  = mcp.build_testbed(channel="all")
        logs.append(f"[MCP] Testbed: channels={tb_result.get('channels')} hostname={tb_result.get('hostname')}")

        # Run agents via MCP
        agent_results = run_domain_expert_agents(mcp, intent, logs, agents_to_run)

        # Flatten risks with agent attribution
        all_risks = []
        for name, r in agent_results.items():
            for ri in r.get("risk_indicators", []):
                all_risks.append({"agent": name, "indicator": ri})

        # MCP tool map for UI display
        command_map = {
            name: {
                "learn_object":           cls.learn_object,
                "critical_show_commands": cls.critical_show_commands,
                "mcp_tools":              ["build_testbed", "learn_feature_state", "run_show_and_parse"],
            }
            for name, cls in DOMAIN_AGENT_CLASSES.items()
            if name in agents_to_run
        }

        mcp.disconnect()
        return jsonify({
            "agents":              agent_results,
            "all_risk_indicators": all_risks,
            "command_map":         command_map,
            "mcp_testbed":         tb_result,
            "selected_agents":     agents_to_run,
            "logs":                logs,
            "timestamp":           time.strftime("%Y-%m-%d %H:%M:%S"),
        })
    except Exception as e:
        tb = traceback.format_exc()
        return jsonify({"error": str(e), "traceback": tb, "logs": logs}), 500


@app.route('/anomalies', methods=['POST'])
def anomalies():
    """Anomaly detection — on-demand, uses Ollama. Saves result to disk."""
    data = request.json
    port = data.get('port', 5017)
    intent = data.get('intent', '')
    intent_mode = data.get('intent_mode', False)
    # On-demand ops always use Ollama
    logs = [f"[ANOMALY] Request port={port} intent_mode={intent_mode} [Ollama]"]

    try:
        saved = SAVED_INVENTORY.get(str(port))
        if saved:
            raw = saved["raw_twin"]
            logs.append("[ANOMALY] Using saved inventory.")
        else:
            logs.append("[ANOMALY] No saved inventory — collecting...")
            raw = collect_device(port, logs)

        result = detect_anomalies(raw, intent if intent_mode else "", "local", logs, intent_mode)
        result["logs"] = logs
        result["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
        # Save to disk
        _save_to_disk(f"anomalies_port_{port}", result)
        return jsonify(result)

    except Exception as e:
        logs.append(f"[FATAL] {str(e)}")
        return jsonify({"error": str(e), "logs": logs}), 500


@app.route('/chat', methods=['POST'])
def chat():
    """Follow-up chat about pipeline results. Uses Claude (falls back to Ollama if no key)."""
    data = request.json
    question = data.get('question', '')
    context = data.get('context', {})
    port = data.get('port', '')
    logs = []
    # Chat always uses Claude
    answer = answer_chat(question, context, "claude", logs)

    # Append to chat history on disk
    chat_key = f"chat_port_{port}" if port else "chat_general"
    history = _load_from_disk(chat_key) or {"messages": []}
    history["messages"].append({
        "q": question, "a": answer,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    })
    _save_to_disk(chat_key, history)

    return jsonify({"answer": answer, "logs": logs})


@app.route('/saved_inventory', methods=['GET'])
def get_saved():
    """Return metadata about saved inventories."""
    return jsonify({
        port: {"timestamp": v["timestamp"], "interface_count": len(v["inventory"].get("interfaces", []))}
        for port, v in SAVED_INVENTORY.items()
    })


@app.route('/clear_inventory', methods=['POST'])
def clear_inventory():
    port = str(request.json.get('port', ''))
    if port in SAVED_INVENTORY:
        del SAVED_INVENTORY[port]
        # Remove from disk
        disk_path = os.path.join(DATA_DIR, f"{_inventory_key(port)}.json")
        try:
            if os.path.exists(disk_path):
                os.remove(disk_path)
        except Exception:
            pass
        return jsonify({"status": "cleared", "port": port})
    return jsonify({"status": "not_found"})


@app.route('/provider', methods=['GET', 'POST'])
def provider_endpoint():
    """
    GET:  returns current LLM provider status and health
    POST: {provider: "claude"|"local"} → switch active provider
    """
    global _user_selected_provider, _claude_balance_ok
    if request.method == 'POST':
        data = request.json or {}
        prov = data.get('provider', 'local')
        if prov == 'reset_claude':
            _claude_balance_ok = True
            return jsonify({"status": "ok", "action": "claude_reset", "provider": _user_selected_provider})
        if prov not in ('claude', 'local'):
            return jsonify({"error": f"Invalid provider '{prov}'. Use 'claude' or 'local'"}), 400
        _user_selected_provider = prov
        # If switching to claude but balance was flagged bad, probe it
        if prov == 'claude':
            _claude_balance_ok = True
        return jsonify({"status": "ok", "provider": _user_selected_provider, **get_llm_status()})
    return jsonify(get_llm_status())


@app.route('/health', methods=['GET'])
def health():
    llm = get_llm_status()
    disk_files = _list_disk_keys()
    return jsonify({
        "status":            "online",
        "version":           "6.0",
        "igraph":            IGRAPH_AVAILABLE,
        "pyats":             PYATS_AVAILABLE,
        "netmiko":           NETMIKO_AVAILABLE,
        "genie_diff":        PYATS_AVAILABLE,
        "mcp_tools":         7,
        "llm":               llm,
        "data_dir":          DATA_DIR,
        "saved_inventories": list(SAVED_INVENTORY.keys()),
        "state_snapshots":   list(STATE_SNAPSHOTS.keys()),
        "netmiko_sessions":  list(NETMIKO_SESSIONS.keys()),
        "disk_files":        disk_files,
    })

@app.route('/llm_status', methods=['GET'])
def llm_status():
    """Lightweight endpoint for frontend to poll Claude balance/fallback status."""
    return jsonify(get_llm_status())

@app.route('/reset_claude', methods=['POST'])
def reset_claude():
    global _claude_balance_ok
    _claude_balance_ok = True
    return jsonify({"status": "reset", "claude_balance_ok": True})


@app.route('/set_provider', methods=['POST'])
def set_provider():
    global _user_selected_provider
    prov = (request.json or {}).get('provider', 'local')
    if prov not in ('claude', 'local'):
        return jsonify({"error": f"Invalid provider '{prov}'"}), 400
    _user_selected_provider = prov
    return jsonify({"status": "ok", "provider": _user_selected_provider})


if __name__ == '__main__':
    print(f"[*] NetBuilder Pro v6 — SRE Platform with MCP + Genie Diff + Domain Expert Agents")
    print(f"[*] igraph: {IGRAPH_AVAILABLE} | pyATS: {PYATS_AVAILABLE} | Netmiko: {NETMIKO_AVAILABLE}")
    print(f"[*] Genie Diff engine: {'ENABLED' if PYATS_AVAILABLE else 'DISABLED (install pyats)'}")
    print(f"[*] MCP tools: 7 registered (connect/learn/parse/exec/snapshot/diff/assess)")
    print(f"[*] Domain Expert Agents: 7 (ospf/bgp/interface/acl/routing/cdp/vlan)")
    print(f"[*] ─── New endpoints ──────────────────────────────────────────")
    print(f"[*]   POST /mcp_pipeline    → Claude MCP tool-calling pipeline")
    print(f"[*]   POST /take_snapshot   → Genie Learn pre/post snapshot")
    print(f"[*]   POST /genie_diff      → Genie Diff(pre, post) → added/removed/modified")
    print(f"[*]   POST /netmiko_exec    → SSH CLI via Netmiko")
    print(f"[*]   POST /set_provider    → Select Claude or Ollama for all ops")
    print(f"[*]   POST /agent_analysis  → Domain Expert Agents (ospf/bgp/interface/acl/routing/cdp/vlan)")
    print(f"[*] ─── Domain Expert Agents ─────────────────────────────────")
    print(f"[*]   Each agent returns: protocol, learn_object, critical_show_commands, analysis, risk_indicators")
    print(f"[*]   MCP translates:    learn_object → device.learn(protocol)")
    print(f"[*]   All 7 run in pipeline + available standalone via /agent_analysis")
    print(f"[*] ─── LLM Routing ───────────────────────────────────────────")
    print(f"[*] igraph: {IGRAPH_AVAILABLE} | pyATS: {PYATS_AVAILABLE}")
    print(f"[*] ─── LLM Routing ───────────────────────────────────────────")
    if ANTHROPIC_API_KEY:
        print(f"[*]   Pipeline + Chat  → Claude Haiku ({CLAUDE_PIPELINE_MODEL})")
        print(f"[*]   Rate limit guard : ≥{CLAUDE_MIN_INTERVAL}s between calls ({60/CLAUDE_MIN_INTERVAL:.0f} RPM max)")
        print(f"[*]   Token budget     : ≤{MAX_INPUT_TOKENS} input / ≤{MAX_OUTPUT_TOKENS} output tokens")
        print(f"[*]   Credit fallback  : Ollama if balance=0 or rate-limited")
    else:
        print(f"[*]   Pipeline + Chat  → Ollama fallback (ANTHROPIC_API_KEY not set)")
    print(f"[*]   On-Demand Ops    → Ollama local ({OLLAMA_MODEL})")
    print(f"[*]   (discover, simulate, anomalies, healing always use Ollama)")
    print(f"[*] ─── Disk Persistence ──────────────────────────────────────")
    print(f"[*]   Data dir: {DATA_DIR}")
    print(f"[*]   Inventories restored: {list(SAVED_INVENTORY.keys()) or 'none'}")
    print(f"[*] ──────────────────────────────────────────────────────────")
    print(f"[*]   NOTE: If Claude shows 'credit balance too low', add credits")
    print(f"[*]   at console.anthropic.com — Haiku costs ~$0.001 per pipeline run")
    print(f"[*]   Tool auto-falls-back to Ollama if balance is exhausted.")
    app.run(host='0.0.0.0', port=5001, debug=False)
