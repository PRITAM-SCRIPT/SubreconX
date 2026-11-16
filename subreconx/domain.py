import re
from urllib.parse import urlsplit
_LABEL_RE=re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
def normalize_domain(value):
    value=value.strip()
    if not value: raise ValueError("empty input")
    if "://" in value:
        host=urlsplit(value).hostname
    else:
        host=value.split("/",1)[0].split("?",1)[0].split("#",1)[0]
        if ":" in host: raise ValueError("ports and IPv6 literals are not accepted")
    if not host: raise ValueError("could not extract hostname")
    host=host.rstrip(".").lower()
    try: host=host.encode("idna").decode("ascii")
    except UnicodeError as e: raise ValueError("invalid internationalized domain name") from e
    return host
def is_valid_domain(domain):
    if len(domain)>253 or "." not in domain: return False
    labels=domain.split(".")
    return len(labels)>=2 and all(_LABEL_RE.fullmatch(x) for x in labels)
def belongs_to_scope(host,target):
    return host==target or host.endswith("."+target)
