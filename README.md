# SubReconX v0.2

Python CLI for passive subdomain discovery and optional HTTP probing.

## Requirements
- Python 3.9+
- Subfinder
- Amass (invoked in passive mode)
- Assetfinder
- ProjectDiscovery httpx (optional, required for `--probe`)

## Run
```powershell
python main.py -d example.com --passive
python main.py -d example.com --passive --probe
```

With `--probe`, structured output may include hostname, HTTP status code, final URL, redirect location, response time, title, server, IP address and failure reason. Some values can be null depending on the installed ProjectDiscovery httpx version and the response.

HTTP probing is active validation, not passive enumeration. A host with no HTTP response is not necessarily dead. Only test domains you own or are explicitly authorized to assess.
