async function hashPassword() {
    const password = document.getElementById("password-hash").value;
    const algo = document.getElementById("hash-algo").value;
    if (!password) {
        alert("Veuillez entrer un mot de passe");
        return;
    }
    const response = await fetch("/api/hash", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password, algorithm: algo }),
    });
    const data = await response.json();
    const resultDiv = document.getElementById("hash-result");
    resultDiv.innerHTML = `
        <h3>Résultat du hachage (${algo.toUpperCase()}):</h3>
        <p><strong>Hash:</strong> ${data.hash}</p>
        <p><strong>Longueur:</strong> ${data.length} caractères</p>
    `;
    resultDiv.classList.add("show");
}

async function scanVirusTotal() {
    const url = document.getElementById("virus-url-input").value.trim();
    const resultDiv = document.getElementById("virus-result");
    if (!url) {
        alert("Veuillez entrer une URL");
        return;
    }
    resultDiv.style.display = "none";
    resultDiv.textContent = "Chargement...";
    try {
        const response = await fetch("/api/virus-total", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
        });
        const data = await response.json();
        if (data.error) {
            resultDiv.textContent = "Erreur: " + data.error;
        } else {
            let scans = data.scans;
            let scanEntries = [];
            for (let engine in scans) {
                let res = scans[engine];
                scanEntries.push(`${engine}: ${res.category} - ${res.result || 'aucun résultat'}`);
            }
            scanEntries.sort();
            resultDiv.innerHTML = `
                <strong>URL Scannée:</strong> ${data.url}<br/>
                <strong>Dernier scan:</strong> ${data.last_analysis_date}<br/>
                <strong>Détections malveillantes:</strong> ${data.positives} / ${data.total}<br/><br/>
                <strong>Détails des scans:</strong><br/>
                <pre>${scanEntries.join('\\n')}</pre>
            `;
        }
    } catch (err) {
        resultDiv.textContent = "Erreur lors de la requête: " + err.message;
    }
    resultDiv.style.display = "block";
}

async function validateEmail() {
    const email = document.getElementById("email-input").value;
    if (!email) {
        alert("Veuillez entrer une adresse email");
        return;
    }
    const response = await fetch("/api/validate-email", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
    });
    const data = await response.json();
    const resultDiv = document.getElementById("email-result");
    resultDiv.innerHTML = `
        <h3>Validation de l'email:</h3>
        <p><strong>Valide:</strong> ${data.valid ? "Oui" : "Non"}</p>
        ${
            data.valid
                ? `
            <p><strong>Domaine:</strong> ${data.domain}</p>
            <p><strong>Risques:</strong> ${data.warnings.length > 0 ? data.warnings.join(", ") : "Aucun"}</p>`
                : `<p><strong>Raison:</strong> ${data.reason}</p>`
        }
    `;
    resultDiv.classList.add("show");
}
