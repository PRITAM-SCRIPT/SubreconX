import shutil, subprocess
def _run(command,timeout):
    try:
        p=subprocess.run(command,capture_output=True,text=True,timeout=timeout,check=False)
        if p.returncode and p.stderr.strip(): print(f"[!] {' '.join(command[:2])} warning: {p.stderr.strip()[:300]}")
        return p.stdout.splitlines()
    except FileNotFoundError: print(f"[!] Required tool not found: {command[0]}")
    except subprocess.TimeoutExpired: print(f"[!] Timed out: {command[0]}")
    except OSError as e: print(f"[!] Could not run {command[0]}: {e}")
    return []
def _extract_hosts(lines):
    from urllib.parse import urlsplit
    hosts=[]
    for line in lines:
        value=line.strip().lower().rstrip(".")
        if "://" in value: value=urlsplit(value).hostname or ""
        value=value.split()[0] if value else ""
        if value: hosts.append(value)
    return hosts
def run_discovery(domain,timeout=300):
    results={}
    tools=[("subfinder",["subfinder","-silent","-d",domain]),
           ("amass",["amass","enum","-passive","-d",domain]),
           ("assetfinder",["assetfinder","--subs-only",domain])]
    for source,cmd in tools:
        if not shutil.which(cmd[0]):
            print(f"[!] {cmd[0]} is not installed or not in PATH; skipping."); results[source]=[]; continue
        print(f"[*] Running {source}...")
        results[source]=_extract_hosts(_run(cmd,timeout))
    return results
