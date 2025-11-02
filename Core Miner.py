# advanced_pool_miner_v5.py
# Build: 2025-11-02
# Robust local pool + miner controller for Miningcore + cpuminer-opt / XMRig
# Key fixes vs v4:
# • Correct Miningcore binary detection (recursive), Windows/DLL logic fixed
# • Live stdout/stderr capture in GUI (no more “opens then closes” with no clue)
# • Coin RPC probe, clearer preflight, stratum readiness wait
# • API resolver hardened (accepts list or {pools:[...]})
# • After download, auto-pin the actual binary folder

import os, json, time, zipfile, shutil, socket, threading, subprocess, platform
from typing import Optional, Dict, Any, List, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import dearpygui.dearpygui as dpg

APP_NAME = "Advanced Pool+Miner"
WIN_W, WIN_H = 1140, 880

# ----- Defaults -----
DEFAULT_MC_URL   = "https://github.com/oliverw/miningcore/archive/refs/tags/v74.zip"  # source tag (warns if no exe/dll)
DEFAULT_CPU_URL  = "https://github.com/JayDDee/cpuminer-opt/releases/download/v25.6/cpuminer-opt-25.6-windows.zip"
DEFAULT_XMRIG_URL= "https://github.com/xmrig/xmrig/releases/download/v6.24.0/xmrig-6.24.0-windows-x64.zip"

# ----- HTTP -----
def http() -> requests.Session:
    s = requests.Session()
    r = Retry(total=5, backoff_factor=0.6,
              status_forcelist=(429,500,502,503,504),
              allowed_methods=frozenset(["GET","POST"]))
    s.mount("http://", HTTPAdapter(max_retries=r))
    s.mount("https://", HTTPAdapter(max_retries=r))
    return s

# ----- Utils -----
def _safe_int(v, d):
    try: return int(str(v).strip())
    except: return d

def _safe_float(v, d):
    try: return float(str(v).strip())
    except: return d

def _append(tag, msg):
    cur = dpg.get_value(tag) or ""
    dpg.set_value(tag, (cur + ("\n" if cur else "") + str(msg)).rstrip())

def _set(tag, msg): dpg.set_value(tag, msg)

def _exists(p): return p and os.path.exists(p)

def _which(cmd): return shutil.which(cmd)

def _tcp(port, host="127.0.0.1", timeout=1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def _is_port_free(port, host="127.0.0.1"):
    try:
        with socket.create_connection((host, port), timeout=0.3):
            return False
    except Exception:
        return True

def _wait_port_open(host: str, port: int, timeout_s: int) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except Exception:
            time.sleep(0.35)
    return False

def _log_to_file(msg):
    with open("app_log.txt", "a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {msg}\n")

# ----- Coin/Algo maps -----
ALGO_BY_SYMBOL = {
    "BTC":"SHA256","BCH":"SHA256",
    "DOGE":"Scrypt","LTC":"Scrypt",
    "ETC":"Etchash","ETHW":"Ethash",
    "RVN":"KawPow","XMR":"RandomX",
    "KAS":"KHeavyHash","ZEC":"Equihash","ERG":"Autolykos",
}
MC_COINNAME_BY_SYMBOL = {
    "BTC":"bitcoin","BCH":"bitcoincash","DOGE":"dogecoin","LTC":"litecoin",
    "ETC":"ethereumclassic","ETHW":"ethereumpow","RVN":"ravencoin","XMR":"monero",
    "KAS":"kaspa","ZEC":"zcash","ERG":"ergo",
}
DEFAULT_RPC_BY_MCNAME = {
    "bitcoin":8332,"dogecoin":22555,"ethereumclassic":8545,
    "litecoin":9332,"ravencoin":8766,"monero":18081,
    "kaspa":16110,"zcash":8232,"ergo":9053,
}
def _mcname_from_symbol(sym: str) -> str:
    return MC_COINNAME_BY_SYMBOL.get(sym.upper(), sym.lower())

# ----- Wallet heuristics (warnings) -----
def _wallet_hint(symbol: str) -> str:
    s = symbol.upper()
    return {
        "DOGE":"DOGE starts with 'D' (not 0x...).",
        "BTC":"BTC starts with 1 / 3 / bc1.",
        "LTC":"LTC starts with L / M / ltc1.",
        "RVN":"RVN often starts with R / r.",
        "XMR":"XMR starts with 4 or 8.",
        "KAS":"KAS uses 'kaspa:' prefix.",
        "ZEC":"ZEC starts with t... or z....",
        "ERG":"ERG usually starts with 9.",
        "ETC":"ETC looks like 0x... (Eth-style).",
    }.get(s, "Check the correct address format for your coin.")

def _wallet_looks_wrong(symbol: str, addr: str) -> bool:
    s = symbol.upper(); a = (addr or "").strip()
    if not a: return True
    if s in ("DOGE","BTC","LTC","RVN") and a.startswith("0x"): return True
    if s=="DOGE" and not a.startswith("D"): return True
    if s=="KAS" and not a.startswith("kaspa:"): return True
    if s=="ZEC" and not (a.startswith("t") or a.startswith("z")): return True
    return False

# ----- Downloads -----
def _download_zip(url: str, dest_dir: str, progress_tag: str, log_tag: str, post_hint: Optional[str]=None):
    try:
        os.makedirs(dest_dir, exist_ok=True)
        zpath = os.path.join(dest_dir, "download.zip")
        dpg.configure_item(progress_tag, show=True)
        with http().get(url, stream=True, timeout=60) as r:
            r.raise_for_status()
            total = int(r.headers.get("content-length", "0") or "0")
            got = 0
            with open(zpath, "wb") as f:
                for chunk in r.iter_content(65536):
                    if chunk:
                        f.write(chunk)
                        got += len(chunk)
                        if total: dpg.set_value(progress_tag, got/total)
        with zipfile.ZipFile(zpath, "r") as z:
            z.extractall(dest_dir)
        try: os.remove(zpath)
        except: pass
        # auto-pin discovered binary subfolder
        picked = _autopin_binary_dir(dest_dir, ["Miningcore.exe","Miningcore.dll"])
        if picked:
            dpg.set_value("mc_dir", picked)
            _append(log_tag, f"Detected Miningcore folder: {picked}")
        if post_hint: _append(log_tag, post_hint)
        _log_to_file(f"Downloaded {url} -> {dest_dir}")
    except Exception as e:
        _append(log_tag, f"Download error: {e}")
        _log_to_file(f"Download error {url}: {e}")
    finally:
        dpg.configure_item(progress_tag, show=False)

def _autopin_binary_dir(root: str, names: List[str]) -> Optional[str]:
    try:
        for dirpath, _, files in os.walk(root):
            for n in names:
                if n in files: return dirpath
    except Exception:
        pass
    return None

# ===================== Miningcore =====================
PROC = {"mc": None}
MC_READER = {"t": None}

def _daemon_port_guess(mc_coin_name: str) -> int:
    return DEFAULT_RPC_BY_MCNAME.get(mc_coin_name, 8332)

def mc_write_config():
    dpg.set_value("mc_log","")
    coins_raw = (dpg.get_value("mc_coins") or "").strip().lower()
    wallet    = (dpg.get_value("mc_pool_wallet") or "").strip()
    port_start= _safe_int(dpg.get_value("mc_port_start"), 3333)
    api_port  = _safe_int(dpg.get_value("mc_api_port"), 4000)
    db_pass   = (dpg.get_value("mc_db_pass") or "miningpass").strip()
    mc_dir    = (dpg.get_value("mc_dir") or os.getcwd()).strip()
    rpc_user  = (dpg.get_value("mc_rpc_user") or "").strip()
    rpc_pass  = (dpg.get_value("mc_rpc_pass") or "").strip()
    overrides = (dpg.get_value("mc_rpc_over") or "").strip().splitlines()

    if not coins_raw or not wallet:
        _append("mc_log","Enter Coins and Pool Wallet."); return
    if port_start < 1024 or port_start > 65530:
        _append("mc_log","Invalid stratum start port (1024–65530)."); return
    if not _is_port_free(api_port):
        _append("mc_log", f"Warning: API port {api_port} not free; pool may fail to bind.")

    # Build per-coin override map
    ovmap: Dict[str, Tuple[str,int,str,str]] = {}
    for line in overrides:
        parts = [p for p in line.split() if p]
        if len(parts) >= 5:
            coin, host, port, user, pw = parts[:5]
            try: ovmap[coin.lower()] = (host, int(port), user, pw)
            except: pass

    pools = []
    coins = [c for c in (x.strip() for x in coins_raw.split(",")) if c]
    for i, cname in enumerate(coins):
        host, port, user, pw = ("127.0.0.1", _daemon_port_guess(cname), rpc_user, rpc_pass)
        if cname in ovmap: host, port, user, pw = ovmap[cname]
        pools.append({
            "id": f"{cname}-pool",
            "enabled": True,
            "coin": cname,
            "address": wallet,
            "rewardRecipients": [{"address": wallet, "percentage": 100.0}],
            "ports": { str(port_start + i): {
                "listenAddress":"0.0.0.0",
                "difficulty": 0.02,
                "varDiff": {"minDiff":0.01,"maxDiff":100,"targetTime":15,"retargetTime":90,"variancePercent":30}
            }},
            "daemons": [{"host":host,"port":port,"user":user,"password":pw}],
            "paymentProcessing": {"enabled":True,"minimumPayment":0.01,"payoutScheme":"PPLNS","payoutSchemeConfig":{"factor":2.0}}
        })

    cfg = {
        "$schema":"https://raw.githubusercontent.com/oliverw/miningcore/master/src/Miningcore/config.schema.json",
        "logging":{"level":"info","enableConsoleLog":True,"enableConsoleColors":True},
        "persistence":{"postgres":{"host":"127.0.0.1","port":5432,"user":"miningcore","password":db_pass,"database":"miningcore"}},
        "paymentProcessing":{"enabled":True,"interval":600,"shareRecoveryFile":"recovered-shares.txt"},
        "notifications":{"enabled":False},
        "api":{"enabled":True,"listenAddress":"0.0.0.0","port":api_port,"rateLimiting":{"disabled":True}},
        "pools":pools
    }

    try:
        os.makedirs(mc_dir, exist_ok=True)
        with open(os.path.join(mc_dir, "config.json"), "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        _set("mc_status", f"config.json written → {mc_dir}")
        _log_to_file("Miningcore config written")
    except Exception as e:
        _append("mc_log", f"Write error: {e}")
        _log_to_file(f"Config write error: {e}")

def _probe_coin_rpc(host: str, port: int, user: str, pw: str) -> Tuple[bool,str]:
    try:
        r = http().post(f"http://{host}:{port}",
                        json={"jsonrpc":"1.0","id":"probe","method":"getblockchaininfo","params":[]},
                        auth=(user or "", pw or ""), timeout=4)
        if r.ok:
            j = r.json()
            ch = (j.get("result") or {}).get("chain","?")
            bh = (j.get("result") or {}).get("blocks","?")
            return True, f"OK ({ch}, height {bh})"
        return False, f"{r.status_code} {r.text[:120]}"
    except Exception as e:
        return False, str(e)

def mc_probe_daemons():
    dpg.set_value("mc_log","")
    coins_raw = (dpg.get_value("mc_coins") or "").strip().lower()
    if not coins_raw: _append("mc_log","Enter Coins first."); return
    rpc_user  = (dpg.get_value("mc_rpc_user") or "").strip()
    rpc_pass  = (dpg.get_value("mc_rpc_pass") or "").strip()
    overrides = (dpg.get_value("mc_rpc_over") or "").strip().splitlines()
    ovmap = {}
    for line in overrides:
        parts = [p for p in line.split() if p]
        if len(parts) >= 5:
            coin, host, port, user, pw = parts[:5]
            try: ovmap[coin.lower()] = (host, int(port), user, pw)
            except: pass
    for cname in [c for c in (x.strip() for x in coins_raw.split(",")) if c]:
        host, port, user, pw = ("127.0.0.1", _daemon_port_guess(cname), rpc_user, rpc_pass)
        if cname in ovmap: host, port, user, pw = ovmap[cname]
        ok, info = _probe_coin_rpc(host, port, user, pw)
        _append("mc_log", f"[{cname}] RPC {host}:{port} → {'OK' if ok else 'FAIL'} {info}")

def _find_mc_binary(mc_dir: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (exe_path, dll_path) found anywhere below mc_dir"""
    exe_path = dll_path = None
    for root, _, files in os.walk(mc_dir):
        if not exe_path and "Miningcore.exe" in files:
            exe_path = os.path.join(root, "Miningcore.exe")
        if not dll_path and "Miningcore.dll" in files:
            dll_path = os.path.join(root, "Miningcore.dll")
        if exe_path and dll_path: break
    return exe_path, dll_path

def mc_preflight() -> Tuple[bool, Optional[str], Optional[str]]:
    mc_dir  = (dpg.get_value("mc_dir") or os.getcwd()).strip()
    api_port= _safe_int(dpg.get_value("mc_api_port"), 4000)
    exe, dll = _find_mc_binary(mc_dir)

    ok = True
    if platform.system() == "Windows":
        if not exe and not dll:
            _append("mc_log", "Miningcore.exe or Miningcore.dll not found anywhere under the selected folder.")
            ok = False
        # If running DLL on Windows, ensure dotnet is present
        if dll and not _which("dotnet"):
            _append("mc_log", "dotnet runtime not found in PATH (DLL builds require dotnet).")
            ok = False
    else:
        # non-Windows requires DLL + dotnet
        if not dll:
            _append("mc_log", "Miningcore.dll not found; build Miningcore and select that folder.")
            ok = False
        if dll and not _which("dotnet"):
            _append("mc_log", "dotnet runtime not found.")
            ok = False

    if not _tcp(5432):
        _append("mc_log", "PostgreSQL (127.0.0.1:5432) not reachable; Miningcore will exit immediately.")
        ok = False
    if not _is_port_free(api_port):
        _append("mc_log", f"Warning: API port {api_port} appears busy.")

    return ok, exe, dll

def _read_pipe_to_ui(proc: subprocess.Popen, tag: str):
    try:
        for line in iter(proc.stdout.readline, ''):
            if not line: break
            _append(tag, line.rstrip())
    except Exception as e:
        _append(tag, f"[reader] {e}")

def mc_start():
    dpg.set_value("mc_log","")
    ok, exe, dll = mc_preflight()
    if not ok: return
    mc_dir = (dpg.get_value("mc_dir") or os.getcwd()).strip()
    cfg = os.path.join(mc_dir, "config.json")
    if not _exists(cfg):
        _append("mc_log","config.json not found. Write Config first."); return
    try:
        if platform.system() == "Windows" and exe:
            cmd = [exe, "-c", "config.json"]
        elif dll:
            cmd = ["dotnet", dll, "-c", "config.json"]
        else:
            _append("mc_log","No runnable Miningcore binary found."); return

        # capture output to GUI so we see why it exits
        PROC["mc"] = subprocess.Popen(
            cmd, cwd=mc_dir,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1
        )
        _set("mc_status", "Miningcore starting…")
        t = threading.Thread(target=_read_pipe_to_ui, args=(PROC["mc"], "mc_log"), daemon=True)
        t.start(); MC_READER["t"] = t

        # small watchdog: if it dies quickly, tell the user
        def _watch():
            time.sleep(3)
            p = PROC.get("mc")
            if p and p.poll() is not None:
                _append("mc_log", f"[exit code {p.returncode}] Miningcore stopped. See log above (tip: check PostgreSQL and coin RPC).")
                _set("mc_status", "Stopped")
        threading.Thread(target=_watch, daemon=True).start()

        _log_to_file("Miningcore started")
    except Exception as e:
        _append("mc_log", f"Start error: {e}")
        _log_to_file(f"Miningcore start error: {e}")

def mc_stop():
    p = PROC.get("mc")
    if p and p.poll() is None:
        try:
            p.terminate()
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: p.kill()
            _set("mc_status","Stopped")
        except Exception as e:
            _append("mc_log", f"Stop error: {e}")
    else:
        _append("mc_log","No running process.")

def mc_download():
    url  = (dpg.get_value("mc_url") or DEFAULT_MC_URL).strip()
    dest = (dpg.get_value("mc_dir") or os.path.join(os.getcwd(),"Miningcore")).strip()
    dpg.set_value("mc_log","")
    if not url:
        _append("mc_log","Paste URL."); return
    threading.Thread(target=_download_zip,
                     args=(url, dest, "mc_progress", "mc_log",
                           "Note: tag /archive zips are source—no exe/dll. Build or use a release build."),
                     daemon=True).start()

# ===================== Miner control (cpuminer-opt / XMRig) =====================
PROC_MINER = {"p": None}

def miner_download(kind: str):
    tag_map = {
        "cpu": ("cpu_url","cpu_dir","cpu_progress","miner_log"),
        "xmrig": ("xmrig_url","xmrig_dir","xmrig_progress","miner_log"),
    }
    url_tag, dir_tag, prog_tag, log_tag = tag_map[kind]
    url  = (dpg.get_value(url_tag) or (DEFAULT_CPU_URL if kind=="cpu" else DEFAULT_XMRIG_URL)).strip()
    dest = (dpg.get_value(dir_tag) or os.path.join(os.getcwd(), ("cpuminer-opt" if kind=="cpu" else "xmrig"))).strip()
    dpg.set_value(log_tag,"")
    if not url: _append(log_tag,"Paste URL."); return
    threading.Thread(target=_download_zip, args=(url, dest, prog_tag, log_tag, "Extracted."), daemon=True).start()

def _resolve_endpoint(api_base: str, pool_id: str, symbol: str) -> Tuple[str,int,str]:
    base = api_base.rstrip("/")
    why = []
    try:
        r = http().get(f"{base}/api/pools", timeout=6)
        if r.ok:
            data = r.json()
            pools = []
            if isinstance(data, list): pools = data
            elif isinstance(data, dict):
                pools = data.get("pools") or data.get("result") or []
            if pools:
                ids = [str(p.get("id","")) for p in pools]
                _set("miner_last_pools", ", ".join(ids))
                target = None
                if pool_id:
                    target = next((p for p in pools if p.get("id","")==pool_id), None)
                if not target:
                    mcname = _mcname_from_symbol(symbol)
                    for p in pools:
                        c = p.get("coin", {})
                        if (c.get("type","").upper()==symbol.upper()) or (c.get("name","").lower()==mcname):
                            target = p; break
                if target:
                    ports = target.get("ports") or {}
                    if ports:
                        try: port = int(sorted(ports.keys(), key=lambda x:int(x))[0])
                        except: port = int(list(ports.keys())[0])
                        return ("127.0.0.1", port, "api")
                why.append("no matching pool in API")
            else:
                why.append("API returned no pools")
        else:
            why.append(f"API status {r.status_code}")
    except Exception as e:
        why.append(f"API error {e}")

    # fallback from UI coins
    coins_raw = (dpg.get_value("mc_coins") or "").strip().lower()
    port_start= _safe_int(dpg.get_value("mc_port_start"), 3333)
    mcname    = _mcname_from_symbol(symbol)
    coins     = [c for c in (x.strip() for x in coins_raw.split(",")) if c]
    if coins:
        try:
            idx = coins.index(mcname)
            return ("127.0.0.1", port_start + idx, "fallback")
        except ValueError:
            pass
    _append("miner_log", "Endpoint resolver failed: " + "; ".join(why))
    return ("",0,"")

def miner_start():
    dpg.set_value("miner_log","")
    base    = (dpg.get_value("api_base") or "http://127.0.0.1:4000").strip()
    pool_id = (dpg.get_value("mon_pool") or "").strip()
    wallet  = (dpg.get_value("miner_wallet") or "").strip()
    symbol  = (dpg.get_value("miner_coin") or "DOGE").strip().upper()
    worker  = (dpg.get_value("miner_worker") or "worker").strip()
    mtype   = (dpg.get_value("miner_type") or "cpuminer-opt").strip()
    algo    = (dpg.get_value("miner_algo") or ALGO_BY_SYMBOL.get(symbol, "")).strip().lower()

    if _wallet_looks_wrong(symbol, wallet):
        _append("miner_log", f"Wallet might be invalid for {symbol}. {_wallet_hint(symbol)}")

    host, port, how = _resolve_endpoint(base, pool_id, symbol)
    if not host or not port:
        _append("miner_log","Could not resolve pool endpoint."); return

    _append("miner_log", f"Resolved via {how}: {host}:{port}. Waiting for stratum…")
    _wait_port_open(host, port, 30)  # miner will retry anyway

    user = f"{wallet}.{worker}" if worker else wallet
    if mtype == "cpuminer-opt":
        dir_tag, exe_name = "cpu_dir", "cpuminer"
    else:
        dir_tag, exe_name = "xmrig_dir", "xmrig"

    mdir = (dpg.get_value(dir_tag) or os.path.join(os.getcwd(), exe_name)).strip()
    exe = None
    for root, _, files in os.walk(mdir):
        for f in files:
            if f.lower().startswith(exe_name) and (platform.system()=="Windows" and f.lower().endswith(".exe") or platform.system()!="Windows"):
                exe = os.path.join(root, f); break
        if exe: break
    if not exe:
        _append("miner_log", f"{exe_name} not found in {mdir}."); return
    if not algo:
        _append("miner_log","Algorithm required (e.g., scrypt / sha256 / yescrypt / randomx)."); return

    args = [exe, "-a", algo, "-o", f"stratum+tcp://{host}:{port}", "-u", user, "-p", "x"]
    if mtype == "xmrig":
        args += ["--http-port","0"]

    try:
        PROC_MINER["p"] = subprocess.Popen(args, cwd=os.path.dirname(exe),
                                           creationflags=getattr(subprocess,"CREATE_NEW_CONSOLE",0) if platform.system()=="Windows" else 0)
        _set("miner_status", f"{mtype} running ({algo}) → {host}:{port}")
        _log_to_file(f"{mtype} started")
    except Exception as e:
        _append("miner_log", f"Start error: {e}")
        _log_to_file(f"{mtype} start error: {e}")

def miner_stop():
    p = PROC_MINER.get("p")
    if p and p.poll() is None:
        try:
            p.terminate()
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: p.kill()
            _set("miner_status","Stopped")
        except Exception as e:
            _append("miner_log", f"Stop error: {e}")
    else:
        _append("miner_log","No running miner.")

# ===================== Monitor =====================
_last_fetch = 0

def _sum_workers(perf_obj: Dict[str, Any]) -> Optional[float]:
    if not isinstance(perf_obj, dict): return None
    wk = perf_obj.get("workers") or {}
    acc = 0.0
    for w in wk.values():
        try: acc += float(w.get("hashrate", 0) or 0)
        except: pass
    return acc

def monitor_fetch():
    global _last_fetch
    dpg.set_value("mon_log","")
    base   = (dpg.get_value("api_base") or "http://127.0.0.1:4000").strip().rstrip("/")
    poolid = (dpg.get_value("mon_pool") or "").strip()
    wallet = (dpg.get_value("mon_wallet") or "").strip()
    if not poolid or not wallet:
        _append("mon_log","Set Pool Id and Wallet."); return
    try:
        r = http().get(f"{base}/api/pools/{poolid}/miners/{wallet}", timeout=8)
        r.raise_for_status()
        j = r.json()
        body = j.get("result", j)
        pending = body.get("pendingBalance") or body.get("pending")
        paid    = body.get("totalPaid") or body.get("paid")
        perf    = body.get("performance") or {}
        hr      = _sum_workers(perf) if perf else body.get("hashrate")
        _set("mon_stats", f"Pending: {pending}\nTotal Paid: {paid}\nHashrate: {hr}")

        pr = http().get(f"{base}/api/pools/{poolid}/miners/{wallet}/payments?pageSize=15", timeout=8)
        pays = pr.json() if pr.ok else []
        rebuild_payments_table(pays)
        _last_fetch = time.time()
    except Exception as e:
        _append("mon_log", f"{e}")

def heartbeat(_s=None,_a=None,_u=None):
    dpg.set_frame_callback(dpg.get_frame_count()+30, heartbeat)
    interval = max(2, _safe_int(dpg.get_value("mon_interval"), 10))
    if dpg.get_value("mon_auto") and (time.time()-_last_fetch >= interval):
        monitor_fetch()

def rebuild_payments_table(payments: List[Dict[str, Any]]):
    if dpg.does_item_exist("pay_table"):
        dpg.delete_item("pay_table")
    with dpg.table(tag="pay_table", parent="mon_table_holder", header_row=True,
                   resizable=True, borders_innerH=True, borders_innerV=True,
                   borders_outerH=True, borders_outerV=True,
                   policy=dpg.mvTable_SizingStretchProp):
        dpg.add_table_column(label="Time")
        dpg.add_table_column(label="Amount")
        dpg.add_table_column(label="TxId / Address")
        for p in payments:
            with dpg.table_row():
                dpg.add_text(str(p.get("created","")))
                dpg.add_text(str(p.get("amount","")))
                dpg.add_text(str(p.get("transactionConfirmationData") or p.get("txId") or p.get("address") or ""))

# ===================== UI =====================
dpg.create_context()
with dpg.theme(tag="adv_theme"):
    with dpg.theme_component(dpg.mvAll):
        dpg.add_theme_color(dpg.mvThemeCol_WindowBg, (16,16,20))
        dpg.add_theme_color(dpg.mvThemeCol_ChildBg, (18,18,24))
        dpg.add_theme_color(dpg.mvThemeCol_FrameBg, (26,26,34))
        dpg.add_theme_color(dpg.mvThemeCol_Text, (235,235,237))
        dpg.add_theme_color(dpg.mvThemeCol_Border, (50,48,65))
        dpg.add_theme_color(dpg.mvThemeCol_Button, (148,88,255))
        dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (168,112,255))
        dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, (130,70,230))
        dpg.add_theme_color(dpg.mvThemeCol_CheckMark, (200,170,255))
        dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 7)
        dpg.add_theme_style(dpg.mvStyleVar_WindowRounding, 10)
        dpg.add_theme_style(dpg.mvStyleVar_CellPadding, 6, 6)

def _browse_to(tag):
    def _cb(_s, app_data):
        path = app_data.get("file_path_name") or app_data.get("current_path")
        if path: dpg.set_value(tag, path)
    return _cb

with dpg.window(tag="main", label=APP_NAME, width=WIN_W, height=WIN_H):
    dpg.bind_theme("adv_theme")
    with dpg.tab_bar():

        # ---- Pool ----
        with dpg.tab(label="Pool"):
            dpg.add_text("Miningcore multi-coin pool. If it exits, see live log below.", color=(168,112,255))
            dpg.add_input_text(label="Coins (comma)", tag="mc_coins", width=760, hint="dogecoin,bitcoin,ravencoin")
            dpg.add_input_text(label="Pool wallet (payout)", tag="mc_pool_wallet", width=760)
            with dpg.group(horizontal=True):
                dpg.add_input_int(label="Stratum start port", tag="mc_port_start", default_value=3333, width=180)
                dpg.add_input_int(label="API port", tag="mc_api_port", default_value=4000, width=180)
            dpg.add_input_text(label="DB password", tag="mc_db_pass", default_value="miningpass", password=True, width=260)

            dpg.add_separator()
            dpg.add_text("Daemon RPC (global) — override per-coin below", color=(168,112,255))
            with dpg.group(horizontal=True):
                dpg.add_input_text(label="RPC user", tag="mc_rpc_user", width=220)
                dpg.add_input_text(label="RPC pass", tag="mc_rpc_pass", password=True, width=220)
            dpg.add_input_text(label="Per-coin RPC overrides (coin host port user pass, one per line)",
                               tag="mc_rpc_over", width=760, height=90, multiline=True,
                               hint="dogecoin 127.0.0.1 22555 rpcuser rpcpass")

            with dpg.group(horizontal=True):
                dpg.add_input_text(label="Miningcore folder", tag="mc_dir", width=760, hint="Folder containing Miningcore.exe or .dll")
                dpg.add_button(label="Browse…", callback=lambda: dpg.show_item("mc_dir_dialog"))

            with dpg.group(horizontal=True):
                dpg.add_button(label="Write config.json", callback=mc_write_config)
                dpg.add_button(label="Probe coin RPCs", callback=mc_probe_daemons)
                dpg.add_button(label="Start Miningcore", callback=mc_start)
                dpg.add_button(label="Stop Miningcore", callback=mc_stop)
            dpg.add_text("", tag="mc_status")
            dpg.add_input_text(tag="mc_log", multiline=True, readonly=True, width=1060, height=190)

            dpg.add_separator()
            dpg.add_text("Download Miningcore (ZIP)", color=(168,112,255))
            dpg.add_input_text(label="URL", tag="mc_url", width=900, default_value=DEFAULT_MC_URL,
                               hint="Tag /archive zips are source only; no exe/dll.")
            dpg.add_button(label="Download & Extract", callback=mc_download)
            dpg.add_progress_bar(tag="mc_progress", width=1060, show=False)

        # ---- Miner ----
        with dpg.tab(label="Miner"):
            dpg.add_text("cpuminer-opt (CPU) / XMRig (CPU/GPU)", color=(168,112,255))
            with dpg.group(horizontal=True):
                dpg.add_combo(label="Type", items=["cpuminer-opt","xmrig"], tag="miner_type", default_value="cpuminer-opt", width=180)
                dpg.add_input_text(label="Coin", tag="miner_coin", width=120, default_value="DOGE")
                dpg.add_input_text(label="Algo (auto from coin ok)", tag="miner_algo", width=220)
                dpg.add_input_text(label="Worker", tag="miner_worker", width=160, default_value="worker")
            dpg.add_input_text(label="Wallet", tag="miner_wallet", width=760, hint="Use a valid address for the chosen coin")

            with dpg.group(horizontal=True):
                dpg.add_input_text(label="cpuminer-opt folder", tag="cpu_dir", width=760, hint="Folder with cpuminer*.exe")
                dpg.add_button(label="Browse…", callback=lambda: dpg.show_item("cpu_dir_dialog"))
                dpg.add_button(label="Download cpuminer-opt", callback=lambda: miner_download("cpu"))
            dpg.add_progress_bar(tag="cpu_progress", width=1060, show=False)

            with dpg.group(horizontal=True):
                dpg.add_input_text(label="XMRig folder", tag="xmrig_dir", width=760, hint="Folder with xmrig.exe / xmrig")
                dpg.add_button(label="Browse…", callback=lambda: dpg.show_item("xmrig_dir_dialog"))
                dpg.add_button(label="Download XMRig", callback=lambda: miner_download("xmrig"))
            dpg.add_progress_bar(tag="xmrig_progress", width=1060, show=False)

            with dpg.group(horizontal=True):
                dpg.add_button(label="Start Miner", callback=miner_start)
                dpg.add_button(label="Stop Miner", callback=miner_stop)
            dpg.add_text("", tag="miner_status")
            dpg.add_input_text(tag="miner_log", multiline=True, readonly=True, width=1060, height=170)
            dpg.add_text("Pools seen (API):")
            dpg.add_input_text(tag="miner_last_pools", readonly=True, width=1060)

        # ---- Monitor ----
        with dpg.tab(label="Monitor"):
            dpg.add_text("Miningcore live stats", color=(168,112,255))
            dpg.add_input_text(label="API Base", tag="api_base", default_value="http://127.0.0.1:4000", width=360)
            dpg.add_input_text(label="Pool Id", tag="mon_pool", width=240, hint="e.g., dogecoin-pool")
            dpg.add_input_text(label="Wallet", tag="mon_wallet", width=760)
            dpg.add_checkbox(label="Auto refresh", tag="mon_auto", default_value=False)
            dpg.add_input_int(label="Interval (sec)", tag="mon_interval", default_value=10, width=140)
            dpg.add_button(label="Fetch now", callback=monitor_fetch)
            dpg.add_input_text(tag="mon_stats", multiline=True, readonly=True, width=1060, height=96)
            with dpg.group(tag="mon_table_holder"): pass
            dpg.add_input_text(tag="mon_log", multiline=True, readonly=True, width=1060, height=140)

        # ---- Help ----
        with dpg.tab(label="Help"):
            dpg.add_text("Quick Start", color=(168,112,255))
            dpg.add_input_text(multiline=True, readonly=True, width=1060, height=310, default_value=(
                "1) Pool: Coins + payout wallet → Write config.json → Probe coin RPCs → Start Miningcore.\n"
                "   • If the log shows 'Waiting for daemons…', your coin full node RPC isn’t reachable.\n"
                "   • PostgreSQL must be reachable on 127.0.0.1:5432.\n"
                "2) Miner: Pick type, coin, wallet → Start. App resolves stratum via API, else coins list.\n"
                "3) Monitor: API base + Pool Id + Wallet → Fetch or enable Auto.\n"
                "Downloads: Miningcore tag ZIPs are source (no exe/dll). Build or use a release build.\n"
            ))

# File dialogs
with dpg.file_dialog(directory_selector=True, show=False, tag="mc_dir_dialog", callback=_browse_to("mc_dir"), width=700, height=420):
    dpg.add_file_extension(".*")
with dpg.file_dialog(directory_selector=True, show=False, tag="cpu_dir_dialog", callback=_browse_to("cpu_dir"), width=700, height=420):
    dpg.add_file_extension(".*")
with dpg.file_dialog(directory_selector=True, show=False, tag="xmrig_dir_dialog", callback=_browse_to("xmrig_dir"), width=700, height=420):
    dpg.add_file_extension(".*")

# Launch
dpg.create_viewport(title=APP_NAME, width=WIN_W, height=WIN_H)
dpg.setup_dearpygui()
dpg.show_viewport()
dpg.set_primary_window("main", True)
dpg.set_frame_callback(dpg.get_frame_count()+30, heartbeat)
dpg.start_dearpygui()
dpg.destroy_context()
