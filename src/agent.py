import re
import json
from jinja2 import FileSystemLoader, Environment
from datetime import datetime
import requests
from typing import Any
from dotenv import load_dotenv
import os
from pathlib import Path
from structlog import get_logger

logger = get_logger()
local_path: Path = Path(__file__).resolve().parent.parent
dotenv_path = local_path / '.env'
load_dotenv(dotenv_path)

class SOCAgent:
    def __init__(self):
        self.vt_api_key = os.environ.get("VT_API_KEY")
        self.llm_api_key = os.environ.get("LLM_API_KEY")
        self.model_name = os.environ.get("MODEL_NAME")
        self.llm_address = os.environ.get("LLM_ADDRESS")
        self.headers = {
            "Authorization": f"Bearer {self.llm_api_key}",
            "Content-Type": "application/json",
        }

    @staticmethod
    def extract_iocs(events: list[dict]) -> dict[str, list[str]]:
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        hash_pattern = r'\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b'

        ips = set()
        hashes = set()

        for ev in events:
            text = ev["message"]
            found_ips = re.findall(ip_pattern, text)
            found_hashes = re.findall(hash_pattern, text)

            for ip in found_ips:
                if not ip.startswith(("192.168.", "10.", "172.16.", "127.0.0.1")):
                    ips.add(ip)

            for h in found_hashes:
                if len(h) in (32, 40, 64):
                    hashes.add(h.lower())

        return {"ips": list(ips), "hashes": list(hashes)}

    def query_virustotal(self, iocs: dict[str, list[str]]) -> dict[str, Any]:
        results = {"ips": {}, "hashes": {}}
        headers = {"x-apikey": self.vt_api_key}

        for h in iocs["hashes"]:
            try:
                resp = requests.get(f"https://www.virustotal.com/api/v3/files/{h}", headers=headers, timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    stats = data["data"]["attributes"]["last_analysis_stats"]
                    results["hashes"][h] = {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "type": data["data"]["attributes"].get("type_description", "unknown")
                    }
                    logger.info(f"VirusTotal results for {h}: {results["hashes"][h]}")
            except Exception as e:
                logger.error("VirusTotal query failed..", exception=e)
                results["hashes"][h] = {"error": "failed"}

        for ip in iocs["ips"]:
            try:
                resp = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers, timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    stats = data["data"]["attributes"]["last_analysis_stats"]
                    results["ips"][ip] = {
                        "malicious": stats.get("malicious", 0),
                        "country": data["data"]["attributes"].get("country", "Unknown")
                    }
                    logger.info(f"VirusTotal results for {ip}: {results["ips"][ip]}")
            except Exception as e:
                logger.error("VirusTotal query failed..", exception=e)
                results["ips"][ip] = {"error": "failed"}

        return results

    @staticmethod
    def fill_template(prompt_file: str, filling_data: dict[str, str | list]) -> str:
        logger.info(prompt_file)
        file_loader = FileSystemLoader(local_path / "data")
        env = Environment(loader=file_loader)
        template = env.get_template(prompt_file)
        prepare_prompt = template.render(filling_data)

        return prepare_prompt

    def inference(
        self,
        prompt: str,
        temperature: float,
        max_tokens: int,
        **kwargs: Any,
    ) -> str:

        endpoint = f"{self.llm_address}/completions"
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "temperature": temperature,
            "max_tokens": max_tokens,
            **kwargs,
        }

        try:
            response = requests.post(
                url=endpoint,
                headers=self.headers,
                json=payload,
                timeout=180,
            )

            if response.status_code == 200:
                result = response.json()["choices"][0]["text"].strip()
                return result
            else:
                response.raise_for_status()

        except requests.RequestException as e:
            logger.error(f"Request failed: {e}")
            logger.error(prompt)
            return ""

    @staticmethod
    def validate_and_save_report(
        raw_string: str,
    ) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = local_path / "data" / f"soc_report_{timestamp}.json"

        try:
            json_match = re.search(r"\{.*\}", raw_string, re.DOTALL)
            if not json_match:
                raise ValueError("No JSON object found in response")

            json_str = json_match.group(0)
            data = json.loads(json_str)
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            logger.info("Report validated and saved", path=str(filepath))
        except json.JSONDecodeError as e:
            logger.error("Failed to decode JSON", error=str(e), raw_string=raw_string)

    def run(self, events: list[dict[str, Any]]) -> str:
        iocs = self.extract_iocs(events)
        vt_results = self.query_virustotal(iocs)

        malicious_hashes = [
            h for h, v in vt_results["hashes"].items()
            if isinstance(v, dict) and v.get("malicious", 0) > 3
        ]
        malicious_ips = [
            ip for ip, v in vt_results["ips"].items()
            if isinstance(v, dict) and v.get("malicious", 0) > 2
        ]
        data_with_fields = {
            "events": events,
            "malicious_hashes": malicious_hashes,
            "malicious_ips": malicious_ips,
        }
        prompt = self.fill_template(
            prompt_file="prompt_for_analysis.jinja2",
            filling_data=data_with_fields,
        )
        response = self.inference(
            prompt=prompt,
            temperature=0.5,
            max_tokens=500,
        )
        self.validate_and_save_report(response)


if __name__ == "__main__":
    events_path = local_path / "data" / "events.json"
    with open(events_path, "r", encoding="utf-8") as f:
        events = json.load(f)

    agent = SOCAgent()
    response = agent.run(events)