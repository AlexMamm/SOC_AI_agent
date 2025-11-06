# Simple AI Agent for SOC Analysts 

Automatically analyzes raw security events, enriches them with threat intelligence, and generates structured incident reports using a LLM. 
 
## What it does 

1. Extracts IoCs – IPs and file hashes from event logs  
2. Checks VirusTotal – gets reputation for malicious files/hosts  
3. Generates report – via LLM: attack narrative, stages, recommendations  
4. Saves output – validated JSON in ./data/
     

 
## Quick Start 

1. Run command
```python
poetry install
```

2. Configure .env 

```python
VT_API_KEY=
LLM_API_KEY=
MODEL_NAME=
LLM_ADDRESS=
``` 
 
3. Add events 

Put raw events in ./data/events.json: 
```python
[
  {"id": 1, "message": "HTTP GET to suspicious.com, SHA256: a1b2c3..."},
  ...
]
``` 
 
4. Run script
```python
python agent.py
```

Output: ./data/soc_report_YYYYMMDD_HHMMSS.json 
