async function hashPassword() {
    const password = document.getElementById('password-hash').value;
    const algorithm = document.getElementById('hash-algo').value;
    
    if (!password) {
        alert('Entrez un mot de passe');
        return;
    }
    
    const response = await fetch('/api/hash', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({password: password, algo: algorithm})
    });
    
    const result = await response.json();
    console.log('DEBUG:', result);
    const resultDiv = document.getElementById('hash-result');
    
    if (result.error) {
        resultDiv.innerHTML = `<div class="error">❌ ${result.error}</div>`;
    } else {
      
        resultDiv.innerHTML = `
            <div class="success">
                <strong>Algorithme :</strong> ${algorithm}<br>
                <strong>Hash :</strong> <code>${typeof result.hash === 'object' ? JSON.stringify(result.hash) : result.hash}</code><br>
            </div>
        `;
    }
    
    resultDiv.style.display = 'block';
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
    let el = document.getElementById(elementId);
    
    // Si l'élément n'existe pas, le créer dynamiquement
    if (!el) {
        console.warn(`Element ${elementId} introuvable, création dynamique`);
        el = document.createElement('div');
        el.id = elementId;
        el.className = 'result';
        el.style.display = 'none';
        
        // Chercher le parent .tool-body le plus proche du bouton qui a appelé
        const buttons = document.querySelectorAll(`[onclick*="${elementId}"]`);
        if (buttons.length > 0) {
            const toolBody = buttons[0].closest('.tool-body');
            if (toolBody) {
                toolBody.appendChild(el);
            } else {
                document.body.appendChild(el);
            }
        } else {
            document.body.appendChild(el);
        }
    }
    
    el.style.display = 'block';
    el.className = `result ${isError ? 'error' : 'success'}`;
    el.innerHTML = content;
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

// ========== Pentest Nmap Automation ==========

function togglePentestPorts() {
    const mode = document.getElementById('pentest-mode').value;
    const portsGroup = document.getElementById('pentest-ports-group');
    
    // Afficher le champ ports seulement pour le mode "full"
    if (mode === 'full') {
        portsGroup.style.display = 'block';
    } else {
        portsGroup.style.display = 'none';
    }
}

async function runPentestNmap() {
    const target = document.getElementById('pentest-target').value.trim();
    const mode = document.getElementById('pentest-mode').value;
    const ports = document.getElementById('pentest-ports').value.trim();
    const generateReport = document.getElementById('generate-report').checked;
    const resultDiv = document.getElementById('pentest-result');
    
    if (!target) {
        showResult(resultDiv, '❌ Veuillez entrer une cible', 'error');
        return;
    }
    
    showResult(resultDiv, '⏳ Pentest en cours... Cela peut prendre plusieurs minutes', '');
    
    try {
        const response = await fetch('/api/pentest-nmap', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                target,
                scan_mode: mode,
                ports: mode === 'full' ? ports : '1-1000',
                generate_report: generateReport,
                output_dir: 'reports'
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            let html = `<h3>✅ Pentest terminé</h3>`;
            html += `<p><strong>Cible:</strong> ${data.target}</p>`;
            html += `<p><strong>Mode:</strong> ${data.scan_mode}</p>`;
            html += `<p><strong>Scans exécutés:</strong> ${data.scans_executed.join(', ')}</p>`;
            
            if (data.report_file) {
                html += `<p><strong>📄 Rapport:</strong> ${data.report_file}</p>`;
            }
            
            // Afficher les résultats des scans
            if (data.data && data.data.scans) {
                html += '<hr><h4>Résultats détaillés:</h4>';
                
                for (const [scanType, scanData] of Object.entries(data.data.scans)) {
                    html += `<h5>${scanType.toUpperCase()}</h5>`;
                    html += `<pre>${JSON.stringify(scanData, null, 2)}</pre>`;
                }
            }
            
            showResult(resultDiv, html, 'success');
        } else {
            let errorMsg = data.error || 'Erreur inconnue';
            
            if (data.install_instructions) {
                errorMsg += '<br><br><strong>Instructions d\'installation:</strong><ul>';
                for (const [os, cmd] of Object.entries(data.install_instructions)) {
                    errorMsg += `<li><strong>${os}:</strong> <code>${cmd}</code></li>`;
                }
                errorMsg += '</ul>';
            }
            
            if (data.install_command) {
                errorMsg += `<br><strong>Installation module:</strong> <code>${data.install_command}</code>`;
            }
            
            showResult(resultDiv, errorMsg, 'error');
        }
    } catch (error) {
        showResult(resultDiv, `❌ Erreur: ${error.message}`, 'error');
    }
}

// ========== Port Scanner Advanced ==========

async function runPortScanner() {
    const target = document.getElementById('portscan-target').value.trim();
    const portsRange = document.getElementById('portscan-range').value.trim();
    const threads = parseInt(document.getElementById('portscan-threads').value);
    const timeout = parseFloat(document.getElementById('portscan-timeout').value);
    const resultDiv = document.getElementById('portscan-result');
    
    if (!target) {
        showResult(resultDiv, '❌ Veuillez entrer une cible', 'error');
        return;
    }
    
    if (!portsRange.match(/^\d+-\d+$/)) {
        showResult(resultDiv, '❌ Format de ports invalide (ex: 1-1000)', 'error');
        return;
    }
    
    showResult(resultDiv, '⏳ Scan en cours... Cela peut prendre du temps selon le nombre de ports', '');
    
    try {
        const response = await fetch('/api/port-scanner', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                target,
                ports: portsRange,
                threads,
                timeout
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            let html = `<h3>✅ Scan terminé</h3>`;
            html += `<p><strong>Cible:</strong> ${data.target}</p>`;
            html += `<p><strong>Ports scannés:</strong> ${data.ports_scanned} (${data.total_scanned} ports)</p>`;
            html += `<p><strong>Ports ouverts:</strong> ${data.open_ports_count}</p>`;
            
            if (data.open_ports_count > 0) {
                html += '<hr><h4>🔓 Ports ouverts détectés:</h4>';
                html += '<table style="width:100%; border-collapse: collapse; margin-top: 10px;">';
                html += '<tr style="background: rgba(102, 126, 234, 0.2);"><th style="padding: 8px; text-align: left;">Port</th><th style="padding: 8px; text-align: left;">Service</th><th style="padding: 8px; text-align: left;">Bannière</th></tr>';
                
                for (const port of data.open_ports) {
                    html += `<tr style="border-bottom: 1px solid rgba(255,255,255,0.1);">`;
                    html += `<td style="padding: 8px;"><strong>${port.port}</strong></td>`;
                    html += `<td style="padding: 8px;">${port.service}</td>`;
                    html += `<td style="padding: 8px; font-size: 0.85em; word-break: break-all;">${escapeHtml(port.banner)}</td>`;
                    html += `</tr>`;
                }
                
                html += '</table>';
            } else {
                html += '<p>ℹ️ Aucun port ouvert détecté dans cette plage</p>';
            }
            
            showResult(resultDiv, html, 'success');
        } else {
            showResult(resultDiv, `❌ ${data.error}`, 'error');
        }
    } catch (error) {
        showResult(resultDiv, `❌ Erreur: ${error.message}`, 'error');
    }
}

// Helper pour échapper HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}


// ========== SecureVault Functions ==========

let currentVaultMasterPassword = null;
let currentVaultName = 'default';

async function initVault() {
    const masterPw = document.getElementById('vault-master-pw').value;
    const vaultName = document.getElementById('vault-name').value || 'default';
    
    if (!masterPw) {
        showResult('vault-status', '❌ Master password requis', 'error');  // ← STRING pas ELEMENT
        return;
    }
    
    try {
        const response = await fetch('/api/securevault/init', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ master_password: masterPw, vault_name: vaultName })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            currentVaultMasterPassword = masterPw;
            currentVaultName = vaultName;
            showResult('vault-status', `✅ ${data.message}<br>Score: ${data.strength.score}/100 (${data.strength.rating})`, 'success');
        } else {
            let errorMsg = `❌ ${data.error}`;
            
            // SI LE VAULT EXISTE DÉJÀ
            if (data.error.includes('existe déjà')) {
                errorMsg += `<br><br>💡 <strong>Solutions :</strong><ul style="text-align:left; margin:10px;">
                    <li>Utilisez "Déverrouiller" pour accéder au vault existant</li>
                    <li>Changez le nom du vault</li>
                    <li>Ou <button onclick="deleteVault('${vaultName}')" style="background:red;color:white;padding:5px 10px;border:none;cursor:pointer;border-radius:3px;">🗑️ Supprimer le vault existant</button></li>
                </ul>`;
            }
            
            // Afficher les recommandations si password trop faible
            if (data.recommendation) {
                errorMsg += `<br><br>💡 <strong>Recommandation:</strong><br>${data.recommendation}`;
            }
            
            // Afficher le score actuel
            if (data.strength) {
                errorMsg += `<br><br>📊 <strong>Score actuel:</strong> ${data.strength.score}/100 (${data.strength.rating})`;
                errorMsg += `<br><strong>Minimum requis:</strong> 40/100`;
                
                // Détails des critères manquants
                const s = data.strength;
                errorMsg += '<br><br><strong>Critères:</strong><ul style="text-align:left; margin:10px 0;">';
                errorMsg += `<li>${s.has_upper ? '✅' : '❌'} Majuscules</li>`;
                errorMsg += `<li>${s.has_lower ? '✅' : '❌'} Minuscules</li>`;
                errorMsg += `<li>${s.has_digit ? '✅' : '❌'} Chiffres</li>`;
                errorMsg += `<li>${s.has_symbol ? '✅' : '❌'} Symboles (!@#$%)</li>`;
                errorMsg += `<li>${s.length >= 12 ? '✅' : '❌'} 12+ caractères (actuel: ${s.length})</li>`;
                errorMsg += '</ul>';
            }
            
            showResult('vault-status', errorMsg, 'error');  // ← STRING
        }
    } catch (error) {
        showResult('vault-status', `❌ Erreur: ${error.message}`, 'error');  // ← STRING
    }
}



async function deleteVault(vaultName) {
    if (!confirm(`⚠️ ATTENTION : Supprimer le vault "${vaultName}" effacera TOUTES vos données de manière IRRÉVERSIBLE.\n\nContinuer ?`)) {
        return;
    }
    
    const resultDiv = document.getElementById('vault-status');
    showResult(resultDiv, '⏳ Suppression en cours...', '');
    
    try {
        const response = await fetch('/api/securevault/delete-vault', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ vault_name: vaultName })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showResult(resultDiv, `✅ ${data.message}<br>Vous pouvez maintenant créer un nouveau vault.`, 'success');
            currentVaultMasterPassword = null;
            currentVaultName = 'default';
        } else {
            showResult(resultDiv, `❌ ${data.error}`, 'error');
        }
    } catch (error) {
        showResult(resultDiv, `❌ Erreur: ${error.message}`, 'error');
    }
}



async function unlockVault() {
    const masterPw = document.getElementById('vault-master-pw').value;
    const vaultName = document.getElementById('vault-name').value || 'default';
    const resultDiv = document.getElementById('vault-status');
    
    if (!masterPw) {
        showResult(resultDiv, '❌ Master password requis', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/securevault/unlock', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ master_password: masterPw, vault_name: vaultName })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            currentVaultMasterPassword = masterPw;
            currentVaultName = vaultName;
            showResult(resultDiv, `🔓 ${data.message}<br>Entrées: ${data.entries_count}`, 'success');
        } else {
            // ← AJOUTE LES DÉTAILS DE L'ERREUR
            let errorMsg = `❌ ${data.error}`;
            
            // Messages spécifiques selon le code d'erreur
            if (response.status === 404) {
                errorMsg += `<br><br>💡 <strong>Solution:</strong> Le vault "${vaultName}" n'existe pas.<br>Utilisez d'abord "Initialiser le Vault" pour le créer.`;
            } else if (response.status === 401) {
                errorMsg += `<br><br>💡 <strong>Solution:</strong> Vérifiez que le master password est correct.`;
            }
            
            showResult(resultDiv, errorMsg, 'error');
        }
    } catch (error) {
        showResult(resultDiv, `❌ Erreur: ${error.message}`, 'error');
    }
}


async function addVaultEntry() {
    const name = document.getElementById('entry-name').value;
    const username = document.getElementById('entry-username').value;
    const password = document.getElementById('entry-password').value;
    const category = document.getElementById('entry-category').value;
    const resultDiv = document.getElementById('add-entry-result');
    
    if (!currentVaultMasterPassword) {
        showResult(resultDiv, '❌ Déverrouillez d\'abord le vault', 'error');
        return;
    }
    
    if (!name || !username || !password) {
        showResult(resultDiv, '❌ Tous les champs sont requis', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/securevault/add', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                master_password: currentVaultMasterPassword,
                vault_name: currentVaultName,
                name, username, password, category
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showResult(resultDiv, `✅ ${data.message}`, 'success');
            // Clear fields
            document.getElementById('entry-name').value = '';
            document.getElementById('entry-username').value = '';
            document.getElementById('entry-password').value = '';
        } else {
            showResult(resultDiv, `❌ ${data.error}`, 'error');
        }
    } catch (error) {
        showResult(resultDiv, `❌ Erreur: ${error.message}`, 'error');
    }
}

async function listVaultEntries() {
    const resultDiv = document.getElementById('list-entries-result');
    
    if (!currentVaultMasterPassword) {
        showResult(resultDiv, '❌ Déverrouillez d\'abord le vault', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/securevault/list', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                master_password: currentVaultMasterPassword,
                vault_name: currentVaultName
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            let html = `<h4>📋 ${data.total} entrées</h4>`;
            html += '<table style="width:100%; margin-top:10px;"><tr><th>Nom</th><th>Username</th><th>Catégorie</th></tr>';
            
            for (const entry of data.entries) {
                html += `<tr><td>${entry.name}</td><td>${entry.username}</td><td>${entry.category}</td></tr>`;
            }
            html += '</table>';
            
            showResult(resultDiv, html, 'success');
        } else {
            showResult(resultDiv, `❌ ${data.error}`, 'error');
        }
    } catch (error) {
        showResult(resultDiv, `❌ Erreur: ${error.message}`, 'error');
    }
}

async function getVaultEntry() {
    const name = document.getElementById('get-entry-name').value;
    const resultDiv = document.getElementById('get-entry-result');
    
    if (!currentVaultMasterPassword) {
        showResult(resultDiv, '❌ Déverrouillez d\'abord le vault', 'error');
        return;
    }
    
    if (!name) {
        showResult(resultDiv, '❌ Nom de l\'entrée requis', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/securevault/get', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                master_password: currentVaultMasterPassword,
                vault_name: currentVaultName,
                name
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            const entry = data.entry;
            let html = `<h4>🔐 ${entry.name}</h4>`;
            html += `<p><strong>Username:</strong> ${entry.username}</p>`;
            html += `<p><strong>Password:</strong> <span style="background:#000; padding:5px; user-select:all;">${entry.password}</span></p>`;
            html += `<p><strong>Catégorie:</strong> ${entry.category}</p>`;
            if (entry.notes) html += `<p><strong>Notes:</strong> ${entry.notes}</p>`;
            
            showResult(resultDiv, html, 'success');
        } else {
            showResult(resultDiv, `❌ ${data.error}`, 'error');
        }
    } catch (error) {
        showResult(resultDiv, `❌ Erreur: ${error.message}`, 'error');
    }
}

async function enrichIOC() {
    const ioc = document.getElementById('ioc-input').value.trim();
    const iocType = document.getElementById('ioc-type').value;
    const vtApi = document.getElementById('vt-api').value.trim();
    const shodanApi = document.getElementById('shodan-api').value.trim();
    const resultDiv = document.getElementById('ioc-result');
    
    if (!ioc) {
        showResult(resultDiv, '❌ IOC requis', 'error');
        return;
    }
    
    showResult(resultDiv, '⏳ Enrichissement en cours...', '');
    
    try {
        const response = await fetch('/api/ioc-enrich', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                ioc,
                ioc_type: iocType,
                vt_api_key: vtApi,
                shodan_api_key: shodanApi
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            let html = `<h3>🔍 Enrichissement de ${data.ioc}</h3>`;
            
            // VirusTotal
            html += '<hr><h4>🛡️ VirusTotal</h4>';
            if (data.enrichment.virustotal.error) {
                html += `<p style="color:orange;">⚠️ ${data.enrichment.virustotal.error}</p>`;
            } else if (data.enrichment.virustotal.note) {
                html += `<p style="color:gray;">${data.enrichment.virustotal.note}</p>`;
            } else {
                const vt = data.enrichment.virustotal;
                const detections = vt.detections || {};
                html += `<p><strong>Malicious:</strong> <span style="color:${detections.malicious > 0 ? 'red' : 'green'};">${detections.malicious}</span></p>`;
                html += `<p><strong>Suspicious:</strong> ${detections.suspicious}</p>`;
                html += `<p><strong>Harmless:</strong> ${detections.harmless}</p>`;
                html += `<p><strong>Reputation:</strong> ${vt.reputation}</p>`;
                html += `<p><strong>Country:</strong> ${vt.country}</p>`;
                html += `<p><strong>ASN:</strong> ${vt.asn} (${vt.as_owner})</p>`;
            }
            
            // Shodan
            html += '<hr><h4>🌐 Shodan</h4>';
            if (data.enrichment.shodan.error) {
                html += `<p style="color:orange;">⚠️ ${data.enrichment.shodan.error}</p>`;
            } else if (data.enrichment.shodan.note) {
                html += `<p style="color:gray;">${data.enrichment.shodan.note}</p>`;
            } else {
                const shodan = data.enrichment.shodan;
                html += `<p><strong>Organisation:</strong> ${shodan.org}</p>`;
                html += `<p><strong>ISP:</strong> ${shodan.isp}</p>`;
                html += `<p><strong>Localisation:</strong> ${shodan.city}, ${shodan.country}</p>`;
                html += `<p><strong>Ports ouverts (${shodan.total_ports}):</strong> ${shodan.open_ports.join(', ')}</p>`;
                html += `<p><strong>OS:</strong> ${shodan.os}</p>`;
                
                if (shodan.total_vulns > 0) {
                    html += `<p style="color:red;"><strong>⚠️ Vulnérabilités (${shodan.total_vulns}):</strong> ${shodan.vulns.join(', ')}</p>`;
                } else {
                    html += `<p style="color:green;">✅ Aucune vulnérabilité connue</p>`;
                }
            }
            
            showResult(resultDiv, html, 'success');
        } else {
            showResult(resultDiv, `❌ ${data.error}`, 'error');
        }
    } catch (error) {
        showResult(resultDiv, `❌ Erreur: ${error.message}`, 'error');
    }
}

