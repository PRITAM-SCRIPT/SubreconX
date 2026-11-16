import json, shutil, subprocess, tempfile
from pathlib import Path
from urllib.parse import urlsplit

def first(data,*keys):
    for key in keys:
        value=data.get(key)
        if value not in (None,"",[],{}): return value
    return None

def run_httpx(hosts,timeout=30):
    """Use ProjectDiscovery's Go httpx binary, not the Python httpx package."""
    if not shutil.which("httpx"):
        print("[!] ProjectDiscovery httpx binary not found; skipping HTTP probing.")
        return {}
    results={}
    with tempfile.TemporaryDirectory(prefix="subreconx_") as tmp:
        infile=Path(tmp)/"hosts.txt"
        infile.write_text("\\n".join(hosts),encoding="utf-8")
        cmd=["httpx","-silent","-no-color","-json","-status-code","-title",
             "-web-server","-ip","-location","-follow-redirects",
             "-timeout",str(timeout),"-retries","1","-l",str(infile)]
        try:
            proc=subprocess.run(cmd,capture_output=True,text=True,timeout=max(timeout*3,60),check=False)
        except subprocess.TimeoutExpired:
            print("[!] httpx probing timed out."); return results
        except OSError as e:
            print(f"[!] Could not execute ProjectDiscovery httpx: {e}"); return results
        if proc.returncode and proc.stderr.strip():
            print(f"[!] httpx warning: {proc.stderr.strip()[:500]}")
        for line in proc.stdout.splitlines():
            try: item=json.loads(line)
            except json.JSONDecodeError: continue
            raw=first(item,"input","url","host")
            if not raw: continue
            parsed=urlsplit(raw if "://" in raw else "http://"+raw)
            host=(parsed.hostname or "").lower().rstrip(".")
            if not host: continue
            try: status=int(first(item,"status_code","status-code"))
            except (TypeError,ValueError): status=None
            ip=first(item,"host_ip","ip","a")
            if isinstance(ip,list): ip=", ".join(map(str,ip)) or None
            err=first(item,"error","failure_reason")
            results[host]={
              "state":"responded" if status is not None else ("failed" if item.get("failed") or err else "no_status"),
              "status_code":status,
              "final_url":first(item,"final_url","url") or raw,
              "redirect_location":first(item,"location","redirect_location","redirect"),
              "response_time":first(item,"time","response_time","response-time"),
              "title":first(item,"title"),
              "server":first(item,"webserver","web_server","server"),
              "ip_address":ip,
              "failure_reason":str(err) if err else None}
    return results
