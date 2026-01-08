import hashlib
import re
import secrets
import string
import bcrypt

def hash_password_func(data):
    password = data.get("password", "")
    algorithm = data.get("algorithm", "sha256")

    if algorithm == "md5":
        hashed = hashlib.md5(password.encode()).hexdigest()
    elif algorithm == "sha512":
        hashed = hashlib.sha512(password.encode()).hexdigest()
    elif algorithm == "bcrypt":
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode(), salt).decode()
    else:
        hashed = hashlib.sha256(password.encode()).hexdigest()

    return {
        "hash": hashed,
        "length": len(hashed),
        "algorithm": algorithm,
    }

def generate_password_func(data):
    length = data.get("length", 16)
    characters = string.ascii_letters + string.digits + string.punctuation
    password = "".join(secrets.choice(characters) for _ in range(length))
    strength = check_password_strength_func({"password": password})
    return {
        "password": password,
        "length": length,
        "strength": strength["level"],
    }

def check_password_strength_func(data):
    password = data.get("password", "")
    score = 0
    suggestions = []

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        suggestions.append("Utilisez au moins 12 caractères")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        suggestions.append("Ajoutez des lettres majuscules")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        suggestions.append("Ajoutez des lettres minuscules")

    if re.search(r"\d", password):
        score += 1
    else:
        suggestions.append("Ajoutez des chiffres")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        suggestions.append("Ajoutez des caractères spéciaux")

    if score <= 2:
        level = "Faible"
    elif score <= 3:
        level = "Moyen"
    elif score <= 4:
        level = "Fort"
    else:
        level = "Très Fort"

    if not suggestions:
        suggestions.append("Excellent mot de passe!")

    return {"score": score, "level": level, "suggestions": suggestions}

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
