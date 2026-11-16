import argparse, json, sys
from datetime import datetime, timezone
from pathlib import Path
from .domain import normalize_domain, is_valid_domain, belongs_to_scope
from .discovery import run_discovery
from .probe import run_httpx

BANNER = r"""
  ____        _     ____                            __  __
 / ___| _   _| |__ |  _ \ ___  ___ ___  _ __  __  \ \/ /
 \___ \| | | | '_ \| |_) / _ \/ __/ _ \| '_ \ \ \ /\  /
  ___) | |_| | |_) |  _ <  __/ (_| (_) | | | | \ V  V /
 |____/ \__,_|_.__/|_| \_\___|\___\___/|_| |_|  \_/\_/

       INTELLIGENT SUBDOMAIN RECONNAISSANCE FRAMEWORK
"""

def main():
    print(BANNER)
    p = argparse.ArgumentParser(prog="SubReconX", description="Passive subdomain discovery with optional HTTP probing.")
    p.add_argument("-d", "--domain", required=True)
    p.add_argument("--passive", action="store_true")
    p.add_argument("--probe", action="store_true")
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("-o", "--output-dir", default="results")
    p.add_argument("--prefix", default=None)
    args = p.parse_args()

    try:
        domain = normalize_domain(args.domain)
    except ValueError as e:
        print(f"[!] Invalid domain: {e}", file=sys.stderr); raise SystemExit(2)
    if not is_valid_domain(domain):
        print(f"[!] Invalid domain: {args.domain}", file=sys.stderr); raise SystemExit(2)

    print(f"[*] Target: {domain}")
    print("[*] Mode: passive discovery" + (" + HTTP probing" if args.probe else " only"))
    print("[*] Only assess domains you own or are explicitly authorized to test.\\n")

    discovered = run_discovery(domain, timeout=max(1,args.timeout))
    merged = {}
    for source, names in discovered.items():
        for raw in names:
            try: name = normalize_domain(raw)
            except ValueError: continue
            if is_valid_domain(name) and belongs_to_scope(name,domain):
                merged.setdefault(name,set()).add(source)

    records = []
    for name,sources in sorted(merged.items()):
        records.append({"hostname":name,"sources":sorted(sources),"is_root_domain":name==domain,
          "http":{"state":"not_checked","status_code":None,"final_url":None,"redirect_location":None,
          "response_time":None,"title":None,"server":None,"ip_address":None,"failure_reason":None}})

    print("\\n[+] Discovery summary")
    for source,names in discovered.items():
        scoped=set()
        for raw in names:
            try: n=normalize_domain(raw)
            except ValueError: continue
            if is_valid_domain(n) and belongs_to_scope(n,domain): scoped.add(n)
        print(f"    {source:<14} {len(scoped)}")
    print(f"    {'Unique total':<14} {len(records)}")

    if args.probe and records:
        probed=run_httpx([r["hostname"] for r in records],timeout=min(max(args.timeout,1),120))
        for r in records:
            r["http"]=probed.get(r["hostname"],{
              "state":"no_response","status_code":None,"final_url":None,"redirect_location":None,
              "response_time":None,"title":None,"server":None,"ip_address":None,
              "failure_reason":"No result returned by httpx; cause not established"})
        responded=sum(r["http"]["status_code"] is not None for r in records)
        print("\\n[+] HTTP probing summary")
        print(f"    Responded:   {responded}")
        print(f"    No response: {len(records)-responded}")
        print("    No response does not prove that a host is dead.")
        print("\\n[+] HTTP details")
        for r in records:
            h=r["http"]; code=h["status_code"] if h["status_code"] is not None else "-"
            print(f"    {r['hostname']:<38} [{code}] {h['state']}")

    out=Path(args.output_dir); out.mkdir(parents=True,exist_ok=True)
    prefix=args.prefix or domain.replace(".","_")
    stamp=datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    txt=out/f"{prefix}_{stamp}.txt"; js=out/f"{prefix}_{stamp}.json"
    with txt.open("w",encoding="utf-8") as f:
        for r in records:
            h=r["http"]
            if args.probe:
                code=h["status_code"] if h["status_code"] is not None else h["state"]
                f.write(f"{r['hostname']} [{code}]\\n")
                for label,key in [("Final URL","final_url"),("Redirect Location","redirect_location"),
                  ("Response Time","response_time"),("Title","title"),("Server","server"),
                  ("IP Address","ip_address"),("Failure Reason","failure_reason")]:
                    f.write(f"  {label}: {h.get(key) or '-'}\\n")
                f.write("\\n")
            else: f.write(r["hostname"]+"\\n")
    payload={"tool":"SubReconX","version":"0.2.0","target":domain,
      "scan_time_utc":datetime.now(timezone.utc).isoformat(),
      "mode":"passive_plus_http_probe" if args.probe else "passive",
      "count":len(records),"records":records,
      "notes":["HTTP probing is active validation, not passive enumeration.",
       "No HTTP response does not prove a host is dead.",
       "Metadata may be null if the installed httpx version does not return it."]}
    js.write_text(json.dumps(payload,indent=2),encoding="utf-8")
    print("\\n[+] Files saved"); print(f"    TXT : {txt}"); print(f"    JSON: {js}")

if __name__=="__main__": main()
