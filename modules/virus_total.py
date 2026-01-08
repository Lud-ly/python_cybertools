import requests
from datetime import datetime
import base64
import os
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

if not VIRUSTOTAL_API_KEY:
    raise ValueError("VIRUSTOTAL_API_KEY non définie. Ajoute-la dans le fichier .env")

def encode_url_for_vt(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return encoded

def submit_url_to_virustotal(data):
    url = data.get("url", "").strip()
    if not url:
        return {"error": "Aucune URL fournie"}
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.post(
            f"{VT_BASE_URL}/urls",
            headers=headers,
            data={"url": url}
        )
        if response.status_code == 200:
            vt_id = response.json().get("data", {}).get("id")
            return {"message": "URL soumise avec succès", "vt_id": vt_id}
        else:
            return {"error": f"Erreur lors de la soumission ({response.status_code})"}
    except Exception as e:
        return {"error": f"Exception lors de la soumission: {str(e)}"}

def get_url_report_from_virustotal(data):
    url = data.get("url", "").strip()
    vt_id = data.get("vt_id")
    if not url and not vt_id:
        return {"error": "Aucune URL ou ID fournie"}
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    if not vt_id:
        vt_id = encode_url_for_vt(url)
    vt_url = f"{VT_BASE_URL}/urls/{vt_id}"
    try:
        response = requests.get(vt_url, headers=headers)
        if response.status_code == 200:
            j = response.json()
            attr = j.get("data", {}).get("attributes", {})
            last_analysis_stats = attr.get("last_analysis_stats", {})
            last_analysis_date_ts = attr.get("last_analysis_date")
            last_analysis_date = (
                datetime.utcfromtimestamp(last_analysis_date_ts).strftime("%Y-%m-%d %H:%M:%S")
                if last_analysis_date_ts else "N/A"
            )
            return {
                "url": attr.get("url", url),
                "positives": last_analysis_stats.get("malicious", 0),
                "total": sum(last_analysis_stats.values()),
                "scans": attr.get("last_analysis_results", {}),
                "last_analysis_date": last_analysis_date,
                "vt_id": j.get("data", {}).get("id"),
            }
        elif response.status_code == 404:
            return {"error": "URL non trouvée dans la base VirusTotal."}
        else:
            return {"error": f"Erreur VirusTotal {response.status_code}"}
    except Exception as e:
        return {"error": f"Exception lors de la récupération du rapport: {str(e)}"}

# Pour compatibilité avec l'existant
def virus_total_scan(data):
    """Soumet l'URL si besoin puis récupère le rapport."""
    # On tente d'abord de récupérer le rapport
    report = get_url_report_from_virustotal(data)
    if report.get("error") == "URL non trouvée dans la base VirusTotal.":
        # Si non trouvée, on soumet l'URL puis on informe l'utilisateur d'attendre
        submit_result = submit_url_to_virustotal(data)
        if "vt_id" in submit_result:
            return {
                "message": "URL soumise à VirusTotal. Veuillez réessayer dans quelques secondes.",
                "vt_id": submit_result["vt_id"]
            }
        else:
            return submit_result
    return report