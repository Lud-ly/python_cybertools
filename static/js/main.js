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

const API_BASE = window.location.origin;

async function apiCall(endpoint, data) {
    try {
        const response = await fetch(`${API_BASE}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        return await response.json();
    } catch (error) {
        return { error: error.message };
    }
}

function showResult(elementId, content, isError = false) {
    const el = document.getElementById(elementId);
    el.style.display = 'block';
    el.className = `result ${isError ? 'error' : 'success'}`;
    el.innerHTML = content;
}

// Cryptographie
async function hashPassword() {
    const password = document.getElementById('password-hash').value;
    const algorithm = document.getElementById('hash-algo').value;
    if (!password) return showResult('hash-result', 'Mot de passe requis', true);
    
    const result = await apiCall('/api/hash', { password, algorithm });
    if (result.error) {
        showResult('hash-result', `❌ ${result.error}`, true);
    } else {
        showResult('hash-result', `<strong>Hash ${algorithm}:</strong><br><pre>${result.hash || result.hashed_password}</pre>`);
    }
}

async function generatePassword() {
    const length = parseInt(document.getElementById('pwd-length').value);
    const result = await apiCall('/api/generate-password', { length });
    if (result.error) {
        showResult('gen-result', `❌ ${result.error}`, true);
    } else {
        showResult('gen-result', `<strong>Mot de passe généré:</strong><br><pre style="font-size:1.2em;color:#10b981;">${result.password}</pre>`);
    }
}

async function checkStrength() {
    const password = document.getElementById('password-strength').value;
    if (!password) return showResult('strength-result', 'Mot de passe requis', true);
    
    const result = await apiCall('/api/check-strength', { password });
    if (result.error) {
        showResult('strength-result', `❌ ${result.error}`, true);
    } else {
        showResult('strength-result', `<strong>Score:</strong> ${result.strength || result.score}/100<br><strong>Commentaire:</strong> ${result.suggestions || result.feedback || 'Aucun'}`);
    }
}

async function validateEmail() {
    const email = document.getElementById('email-input').value;
    if (!email) return showResult('email-result', 'Email requis', true);
    
    const result = await apiCall('/api/validate-email', { email });
    if (result.error) {
        showResult('email-result', `❌ ${result.error}`, true);
    } else {
        showResult('email-result', `<strong>Valide:</strong> ${result.valid ? '✅ Oui' : '❌ Non'}<br>${result.message || ''}`);
    }
}

// Analyse & Détection
async function scanVirusTotal() {
    const url = document.getElementById('virus-url').value;
    if (!url) return showResult('virus-result', 'URL requise', true);
    
    showResult('virus-result', '<div class="loading"></div> Analyse en cours...');
    const result = await apiCall('/api/virus-total', { url });
    
    if (result.error) {
        showResult('virus-result', `❌ ${result.error}`, true);
    } else {
        showResult('virus-result', `<pre>${JSON.stringify(result, null, 2)}</pre>`);
    }
}

function togglePorts() {
    const scanType = document.getElementById('scan-type').value;
    document.getElementById('ports-group').style.display = scanType === 'custom' ? 'block' : 'none';
}

async function runNmapScan() {
    const target = document.getElementById('nmap-target').value;
    const scanType = document.getElementById('scan-type').value;
    const ports = document.getElementById('ports-range').value;
    
    if (!target) return showResult('nmap-result', 'Cible requise', true);
    
    showResult('nmap-result', '<div class="loading"></div> Scan en cours...');
    const result = await apiCall('/api/nmap', { target, scan_type: scanType, ports });
    
    if (result.error) {
        showResult('nmap-result', `❌ ${result.error}`, true);
    } else {
        showResult('nmap-result', `<pre>${JSON.stringify(result, null, 2)}</pre>`);
    }
}

async function analyzeLogs() {
    const logContent = document.getElementById('log-content').value;
    if (!logContent) return showResult('log-result', 'Logs requis', true);
    
    showResult('log-result', '<div class="loading"></div> Analyse en cours...');
    const result = await apiCall('/api/log-analyzer', { log_content: logContent });
    
    if (result.error) {
        showResult('log-result', `❌ ${result.error}`, true);
    } else {
        const analysis = result.analysis;
        let html = `<h3>📊 Résumé</h3>
            <p>Total requêtes: ${analysis.summary.total_requests}</p>
            <p>IPs uniques: ${analysis.summary.unique_ips}</p>
            <p>Requêtes suspectes: ${analysis.summary.suspicious_requests}</p>
            <h3>🚨 Top IPs Brute Force</h3>`;
        
        analysis.brute_force_ips.slice(0, 5).forEach(item => {
            html += `<p>${item.ip}: ${item.attempts} tentatives</p>`;
        });
        
        html += `<h3>⚠️ Chemins Suspects</h3>`;
        analysis.suspicious_paths.slice(0, 5).forEach(item => {
            html += `<p>${item.path}: ${item.count} accès</p>`;
        });
        
        showResult('log-result', html);
    }
}

async function enrichIOC() {
    const ioc = document.getElementById('ioc-input').value;
    const iocType = document.getElementById('ioc-type').value;
    const vtApi = document.getElementById('vt-api').value;
    const shodanApi = document.getElementById('shodan-api').value;
    
    if (!ioc) return showResult('ioc-result', 'IOC requis', true);
    
    showResult('ioc-result', '<div class="loading"></div> Enrichissement en cours...');
    const result = await apiCall('/api/ioc-enrich', {
        ioc, type: iocType, vt_api_key: vtApi, shodan_api_key: shodanApi
    });
    
    if (result.error) {
        showResult('ioc-result', `❌ ${result.error}`, true);
    } else {
        showResult('ioc-result', `<pre>${JSON.stringify(result.data, null, 2)}</pre>`);
    }
}

// Reconnaissance
async function analyzeGit() {
    const repo = document.getElementById('git-repo').value;
    if (!repo) return showResult('git-result', 'URL requise', true);
    
    showResult('git-result', '<div class="loading"></div> Analyse...');
    const result = await apiCall('/api/gitstats', { repo_url: repo });
    
    if (result.error) {
        showResult('git-result', `❌ ${result.error}`, true);
    } else {
        showResult('git-result', `<pre>${JSON.stringify(result, null, 2)}</pre>`);
    }
}

async function enumerateWeb() {
    const url = document.getElementById('web-enum-url').value;
    if (!url) return showResult('web-enum-result', 'URL requise', true);
    
    showResult('web-enum-result', '<div class="loading"></div> Énumération...');
    const result = await apiCall('/api/web-enum', { url });
    
    if (result.error) {
        showResult('web-enum-result', `❌ ${result.error}`, true);
    } else {
        showResult('web-enum-result', `<pre>${JSON.stringify(result, null, 2)}</pre>`);
    }
}

async function osintSearch() {
    const target = document.getElementById('osint-target').value;
    if (!target) return showResult('osint-result', 'Cible requise', true);
    
    showResult('osint-result', '<div class="loading"></div> Recherche...');
    const result = await apiCall('/api/osint', { target });
    
    if (result.error) {
        showResult('osint-result', `❌ ${result.error}`, true);
    } else {
        showResult('osint-result', `<pre>${JSON.stringify(result, null, 2)}</pre>`);
    }
}

async function bruteForce() {
    const url = document.getElementById('bf-url').value;
    const username = document.getElementById('bf-username').value;
    const wordlist = document.getElementById('bf-wordlist').value.split('\n').filter(p => p.trim());
    
    if (!url || !username || wordlist.length === 0) {
        return showResult('bf-result', 'Tous les champs requis', true);
    }
    
    showResult('bf-result', '<div class="loading"></div> Test...');
    const result = await apiCall('/api/http-bruteforce', { url, username, wordlist });
    
    if (result.error) {
        showResult('bf-result', `❌ ${result.error}`, true);
    } else {
        showResult('bf-result', `<pre>${JSON.stringify(result, null, 2)}</pre>`);
    }
}