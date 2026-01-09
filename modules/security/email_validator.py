import hashlib
import re
import secrets
import string
import bcrypt

def validate_email_func(data):
    email = data.get("email", "")
    email_pattern = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    valid = bool(email_pattern.match(email))
    if valid:
        domain = email.split("@")[1]
        warnings = []
        suspicious_domains = [
            "tempmail",
            "throwaway",
            "guerrillamail",
            "10minutemail",
        ]
        if any(susp in domain.lower() for susp in suspicious_domains):
            warnings.append("Domaine d'email temporaire détecté")
        return {"valid": True, "domain": domain, "warnings": warnings}
    else:
        return {"valid": False, "reason": "Format d'email invalide"}
