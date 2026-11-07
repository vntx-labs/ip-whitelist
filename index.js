const http = require('http');
const httpProxy = require('http-proxy');
const axios = require('axios');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const cookie = require('cookie');
const { OAuth2Client } = require('google-auth-library');
const crypto = require('crypto');

// --- ENVIRONMENT VARIABLEN EINLESEN ---
const PORT = process.env.PORT || 3000;
const GIST_WHITELIST_URL = process.env.GIST_WHITELIST_URL;
const GIST_DB_URL = process.env.GIST_DB_URL;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const GIST_PATCH_API_URL = process.env.GIST_PATCH_API_URL;
const NGROK_DOMAIN = process.env.NGROK_DOMAIN;
const NGROK_USER = process.env.NGROK_USER;
const NGROK_PASS = process.env.NGROK_PASS;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "info.orbit.link@gmail.com";
const SECRET_KEY = process.env.SECRET_KEY || crypto.randomBytes(32).toString('hex');

// Sicherheits-Check beim Start
const missingEnvs = [];
if (!GIST_WHITELIST_URL) missingEnvs.push('GIST_WHITELIST_URL');
if (!GIST_DB_URL) missingEnvs.push('GIST_DB_URL');
if (!GITHUB_TOKEN) missingEnvs.push('GITHUB_TOKEN');
if (!GIST_PATCH_API_URL) missingEnvs.push('GIST_PATCH_API_URL');
if (!NGROK_DOMAIN) missingEnvs.push('NGROK_DOMAIN');
if (!NGROK_USER) missingEnvs.push('NGROK_USER');
if (!NGROK_PASS) missingEnvs.push('NGROK_PASS');
if (!GOOGLE_CLIENT_ID) missingEnvs.push('GOOGLE_CLIENT_ID');

if (missingEnvs.length > 0) {
    console.error(`[FATAL] Fehlende Environment Variables: ${missingEnvs.join(', ')}`);
    process.exit(1);
}

const authHeader = 'Basic ' + Buffer.from(`${NGROK_USER}:${NGROK_PASS}`).toString('base64');
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// --- DATENBANK SETUP (Im RAM, synchronisiert via Gist URL) ---
const db = new Database(':memory:');

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password_hash TEXT,
        auth_provider TEXT DEFAULT 'local',
        traffic_used INTEGER DEFAULT 0,
        traffic_limit INTEGER DEFAULT 10737418240, -- 10 GB Standard
        is_banned INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER,
        is_raspi INTEGER DEFAULT 0,
        is_dashboard INTEGER DEFAULT 0,
        is_admin INTEGER DEFAULT 0,
        expires_at DATETIME,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS request_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        method TEXT,
        url TEXT,
        ip TEXT,
        bytes_transferred INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
`);

// DSGVO Auto-Cleanup: Logs nach 14 Tagen löschen
setInterval(() => {
    db.prepare("DELETE FROM request_logs WHERE timestamp < datetime('now', '-14 days')").run();
}, 3600000);

const proxy = httpProxy.createProxyServer({});

let whitelist = [];
let isUpdatingWhitelist = false;

// 1. IP-Whitelist via URL laden
async function updateWhitelist() {
    if (isUpdatingWhitelist) return;
    isUpdatingWhitelist = true;
    try {
        const response = await axios.get(`${GIST_WHITELIST_URL}?nocache=${Date.now()}`, { timeout: 5000 });
        if (response.data) {
            const rawData = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
            whitelist = rawData.split('\n')
                .map(ip => ip.replace('\r', '').replace(/"/g, '').trim())
                .filter(ip => ip.length > 0);
        }
    } catch (e) { 
        console.error("[WHITELIST] Fehler beim Laden des Gists:", e.message); 
    } finally {
        isUpdatingWhitelist = false;
    }
}
setInterval(updateWhitelist, 300000);
setTimeout(updateWhitelist, 1000);

// 2. DB-State laden
async function loadDatabaseFromGist() {
    try {
        const res = await axios.get(`${GIST_DB_URL}?nocache=${Date.now()}`, { 
            headers: { Authorization: `Bearer ${GITHUB_TOKEN.trim()}` },
            timeout: 5000 
        });
        if (res.data && res.data.users) {
            const insertUser = db.prepare('INSERT OR REPLACE INTO users (id, email, password_hash, auth_provider, traffic_used, traffic_limit, is_banned, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
            for (const u of res.data.users || []) {
                insertUser.run(u.id, u.email, u.password_hash, u.auth_provider, u.traffic_used, u.traffic_limit, u.is_banned || 0, u.created_at);
            }
            const insertSession = db.prepare('INSERT OR REPLACE INTO sessions (token, user_id, is_raspi, is_dashboard, is_admin, expires_at) VALUES (?, ?, ?, ?, ?, ?)');
            for (const s of res.data.sessions || []) {
                insertSession.run(s.token, s.user_id, s.is_raspi || 0, s.is_dashboard || 0, s.is_admin || 0, s.expires_at);
            }
            console.log(`[DB] ${res.data.users.length} Nutzer via Gist-URL in den RAM geladen.`);
        }
    } catch (e) {
        console.error("[DB] Konnte Gist-DB via URL nicht laden:", e.message);
    }
}
setTimeout(loadDatabaseFromGist, 2500);

// 3. DB-State ins Gist sichern
async function syncDatabaseToGist() {
    try {
        const users = db.prepare('SELECT * FROM users').all();
        const sessions = db.prepare('SELECT * FROM sessions').all();
        const payload = JSON.stringify({ users, sessions }, null, 2);

        await axios.patch(GIST_PATCH_API_URL, {
            files: {
                'titan_users.json': { content: payload }
            }
        }, {
            headers: { 
                Authorization: `Bearer ${GITHUB_TOKEN.trim()}`,
                'User-Agent': 'Titan-Gateway'
            },
            timeout: 5000
        });
    } catch (e) {
        console.error("[DB Sync] Fehler beim Speichern ins Gist:", e.message);
    }
}
setInterval(syncDatabaseToGist, 60000);

// --- PROXY HEADER & TRAFFIC ZÄHLUNG ---
proxy.on('proxyRes', function (proxyRes, req, res, options) {
    const contentType = proxyRes.headers['content-type'] || '';
    const url = req.url || '';
        
    if (contentType.includes('audio') || contentType.includes('mpeg') || url.includes('/radio')) {
        proxyRes.headers['content-type'] = 'audio/mpeg';
        proxyRes.headers['x-content-type-options'] = 'nosniff';
        proxyRes.headers['cache-control'] = 'no-cache, no-store, must-revalidate';
        proxyRes.headers['connection'] = 'keep-alive';
        delete proxyRes.headers['content-length'];
        delete proxyRes.headers['transfer-encoding'];
    }

    if (req.titanUser && req.titanSession.is_raspi && proxyRes.headers['content-length']) {
        const bytes = parseInt(proxyRes.headers['content-length'], 10) || 0;
        db.prepare('UPDATE users SET traffic_used = traffic_used + ? WHERE id = ?').run(bytes, req.titanUser.id);
        
        let clientIp = req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0].trim() : req.socket.remoteAddress;
        if (clientIp.startsWith('::ffff:')) clientIp = clientIp.replace('::ffff:', '');
        
        db.prepare('INSERT INTO request_logs (user_id, method, url, ip, bytes_transferred) VALUES (?, ?, ?, ?, ?)')
          .run(req.titanUser.id, req.method, req.url, clientIp, bytes);
    }
});

// --- HELPER & SECURITY HASH ---
function generateTimeHash(token) {
    const hourBucket = Math.floor(Date.now() / (1000 * 60 * 60));
    return crypto.createHmac('sha256', SECRET_KEY).update(token + hourBucket).digest('hex');
}

function verifyTimeHash(token, hash) {
    const currentHour = Math.floor(Date.now() / (1000 * 60 * 60));
    const h1 = crypto.createHmac('sha256', SECRET_KEY).update(token + currentHour).digest('hex');
    const h2 = crypto.createHmac('sha256', SECRET_KEY).update(token + (currentHour - 1)).digest('hex');
    return hash === h1 || hash === h2;
}

function getValidSession(req) {
    const cookies = cookie.parse(req.headers.cookie || '');
    const token = cookies.gateway_session; // NUTZT JETZT GATEWAY SESSION!
    const timeHash = cookies.gateway_time_hash;
    if (!token || !timeHash) return null;

    if (!verifyTimeHash(token, timeHash)) return null;

    const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
    if (!session || new Date(session.expires_at) < new Date()) {
        if (session) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
        return null;
    }
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
    if (!user || user.is_banned) return null;
    return { session, user };
}

function createSession(res, userId, mode) {
    const token = crypto.randomBytes(32).toString('hex');
    const isRaspi = mode === 'raspi' ? 1 : 0;
    const isDashboard = mode === 'dashboard' ? 1 : 0;
    const isAdmin = mode === 'admin' ? 1 : 0;

    const maxAge = isAdmin ? 12 * 60 * 60 : 24 * 60 * 60;
    const expires = new Date(Date.now() + maxAge * 1000);

    db.prepare('INSERT INTO sessions (token, user_id, is_raspi, is_dashboard, is_admin, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(token, userId, isRaspi, isDashboard, isAdmin, expires.toISOString());

    const timeHash = generateTimeHash(token);
    
    const cookieSettings = { httpOnly: true, path: '/', maxAge, sameSite: 'lax' };
    const cookiesArray = [
        cookie.serialize('gateway_session', token, cookieSettings),
        cookie.serialize('gateway_time_hash', timeHash, cookieSettings)
    ];

    // WICHTIG: titan_session wird NUR dann gesetzt, wenn der Modus strikt 'raspi' ist!
    if (mode === 'raspi') {
        cookiesArray.push(cookie.serialize('titan_session', token, cookieSettings));
    } else {
        // Ansonsten alten titan_session Cookie löschen, falls vorhanden
        cookiesArray.push(cookie.serialize('titan_session', '', { ...cookieSettings, maxAge: 0 }));
    }

    res.setHeader('Set-Cookie', cookiesArray);
}

function parsePostData(req) {
    return new Promise((resolve) => {
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', () => {
            const params = new URLSearchParams(body);
            const data = {};
            for (const [key, value] of params.entries()) data[key] = value;
            resolve(data);
        });
    });
}

// --- UI: STARTSEITE ---
function renderStartPage(req, res, userEmail = null, errorMessage = '') {
    const isAdmin = userEmail === ADMIN_EMAIL;
    const host = req.headers['host'] || 'ip-whitelist.onrender.com';
    const protocol = req.headers['x-forwarded-proto'] || 'https';
    const absoluteLoginUri = `${protocol}://${host}/api/auth/google`;

    const html = `
    <!DOCTYPE html>
    <html lang="de">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>TITAN GATEWAY — Startseite</title>
        <script src="https://accounts.google.com/gsi/client" async defer></script>
        <style>
            * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
            body { background: #0d1117; color: #c9d1d9; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
            .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 32px; width: 100%; max-width: 420px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); text-align: center; }
            h1 { font-size: 1.5rem; color: #58a6ff; margin-bottom: 8px; }
            p { font-size: 0.875rem; color: #8b949e; margin-bottom: 24px; }
            .error { background: rgba(248, 81, 73, 0.1); border: 1px solid #f85149; color: #f85149; padding: 10px; border-radius: 6px; font-size: 0.85rem; margin-bottom: 16px; }
            .form-group { margin-bottom: 16px; text-align: left; }
            label { display: block; font-size: 0.85rem; margin-bottom: 6px; color: #8b949e; }
            input[type="email"], input[type="password"] { width: 100%; padding: 10px 12px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-size: 0.9rem; }
            input:focus { border-color: #58a6ff; outline: none; }
            .btn { width: 100%; padding: 12px; border: none; border-radius: 6px; color: #fff; font-weight: 600; cursor: pointer; margin-top: 8px; font-size: 0.9rem; text-decoration: none; display: block; }
            .btn-raspi { background: #238636; } .btn-raspi:hover { background: #2ea043; }
            .btn-dash { background: #1f6feb; } .btn-dash:hover { background: #388bfd; }
            .btn-admin { background: #da3633; } .btn-admin:hover { background: #b31d1c; }
            .divider { display: flex; align-items: center; text-align: center; margin: 20px 0; color: #484f58; font-size: 0.8rem; }
            .divider::before, .divider::after { content: ''; flex: 1; border-bottom: 1px solid #30363d; }
            .divider::before { margin-right: .5em; } .divider::after { margin-left: .5em; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>🛡️ TITAN GATEWAY</h1>
            <p>${userEmail ? `Eingeloggt als: <strong>${userEmail}</strong>` : 'Bitte anmelden oder registrieren'}</p>
            ${errorMessage ? `<div class="error">${errorMessage}</div>` : ''}

            ${!userEmail ? `
                <div id="g_id_onload" data-client_id="${GOOGLE_CLIENT_ID}" data-login_uri="${absoluteLoginUri}" data-auto_prompt="false"></div>
                <div class="g_id_signin" data-type="standard" data-size="large" data-theme="filled_black" data-text="sign_in_with" data-shape="rect" data-logo_alignment="center" data-width="356"></div>

                <div class="divider">ODER MIT E-MAIL</div>

                <form action="/api/auth/login" method="POST">
                    <div class="form-group">
                        <label>E-Mail Adresse</label>
                        <input type="email" name="email" required autocomplete="username">
                    </div>
                    <div class="form-group">
                        <label>Passwort</label>
                        <input type="password" name="password" required autocomplete="current-password">
                    </div>
                    <button type="submit" class="btn btn-raspi">Anmelden / Registrieren</button>
                </form>
            ` : `
                <form action="/api/select-mode" method="POST">
                    <button type="submit" name="mode" value="raspi" class="btn btn-raspi">1. Weiter auf Titan</button>
                    <button type="submit" name="mode" value="dashboard" class="btn btn-dash" style="margin-top:10px;">2. Weiter zum Titan Gateway Dashboard</button>
                    ${isAdmin ? `<button type="submit" name="mode" value="admin" class="btn btn-admin" style="margin-top:10px;">3. Weiter zum Titan Gateway Admin-Dashboard</button>` : ''}
                </form>
            `}
        </div>
    </body>
    </html>
    `;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
}

// --- HAUPTSERVER & ROUTING ---
http.createServer(async (req, res) => {
    let clientIp = req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0].trim() : req.socket.remoteAddress;
    if (clientIp.startsWith('::ffff:')) clientIp = clientIp.replace('::ffff:', '');

    // 1. WHITELIST CHECK
    if (whitelist.includes(clientIp)) {
        return passToProxy(req, res);
    }

    // 2. LOGIN API (E-Mail / Passwort) - Setzt NUR gateway_session, KEIN titan_session!
    if (req.url === '/api/auth/login' && req.method === 'POST') {
        const { email, password } = await parsePostData(req);
        if (!email || !password) return renderStartPage(req, res, null, 'Bitte E-Mail und Passwort eingeben.');

        let user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
        if (!user) {
            const hash = bcrypt.hashSync(password, 10);
            const result = db.prepare('INSERT INTO users (email, password_hash, auth_provider) VALUES (?, ?, ?)').run(email, hash, 'local');
            user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
        } else if (user.password_hash) {
            if (!bcrypt.compareSync(password, user.password_hash)) return renderStartPage(req, res, null, 'Passwort ist nicht korrekt.');
        }

        createSession(res, user.id, 'none'); 
        res.writeHead(302, { 'Location': '/' });
        return res.end();
    }

    // 3. GOOGLE OAUTH LOGIN - Setzt NUR gateway_session, KEIN titan_session!
    if (req.url === '/api/auth/google' && req.method === 'POST') {
        const { credential } = await parsePostData(req);
        try {
            const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
            const email = ticket.getPayload().email;

            let user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
            if (!user) {
                const result = db.prepare('INSERT INTO users (email, auth_provider) VALUES (?, ?)').run(email, 'google');
                user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
            }

            createSession(res, user.id, 'none');
            res.writeHead(302, { 'Location': '/' });
            return res.end();
        } catch (e) {
            return renderStartPage(req, res, null, 'Google Login fehlgeschlagen.');
        }
    }

    // 4. MODUS AUSWAHL
    if (req.url === '/api/select-mode' && req.method === 'POST') {
        const active = getValidSession(req);
        if (!active) {
            res.writeHead(302, { 'Location': '/' });
            return res.end();
        }

        const { user } = active;
        const data = await parsePostData(req);
        const mode = data.mode;

        if (mode === 'raspi') {
            // Hier wird erst der titan_session Cookie aktiviert!
            createSession(res, user.id, 'raspi');
            res.writeHead(302, { 'Location': '/' });
            return res.end();
        }
        if (mode === 'dashboard') {
            createSession(res, user.id, 'dashboard');
            res.writeHead(302, { 'Location': '/dashboard' });
            return res.end();
        }
        if (mode === 'admin' && user.email === ADMIN_EMAIL) {
            createSession(res, user.id, 'admin');
            res.writeHead(302, { 'Location': '/admin' });
            return res.end();
        }

        res.writeHead(302, { 'Location': '/' });
        return res.end();
    }

    // 5. USER DASHBOARD (/dashboard)
    if (req.url === '/dashboard' && req.method === 'GET') {
        const active = getValidSession(req);
        if (!active || !active.session.is_dashboard) {
            res.writeHead(302, { 'Location': '/' });
            return res.end();
        }

        const { user } = active;
        const logs = db.prepare('SELECT method, url, bytes_transferred, timestamp FROM request_logs WHERE user_id = ? ORDER BY id DESC LIMIT 50').all();
        const percentUsed = Math.min(100, (user.traffic_used / user.traffic_limit) * 100).toFixed(2);
        const usedGB = (user.traffic_used / (1024 * 1024 * 1024)).toFixed(2);
        const limitGB = (user.traffic_limit / (1024 * 1024 * 1024)).toFixed(2);

        const html = `
        <!DOCTYPE html>
        <html lang="de">
        <head>
            <meta charset="UTF-8">
            <title>TITAN GATEWAY — Dashboard</title>
            <style>
                * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
                body { background: #0d1117; color: #c9d1d9; padding: 40px; }
                .container { max-width: 900px; margin: 0 auto; }
                .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 24px; margin-bottom: 24px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
                h1, h2 { color: #58a6ff; margin-bottom: 16px; }
                .progress-bg { background: #30363d; border-radius: 6px; height: 16px; overflow: hidden; margin: 12px 0; }
                .progress-bar { background: #238636; height: 100%; width: ${percentUsed}%; }
                table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 0.85rem; }
                th, td { text-align: left; padding: 10px; border-bottom: 1px solid #30363d; color: #8b949e; }
                th { color: #58a6ff; }
                .badge { background: #21262d; padding: 4px 8px; border-radius: 4px; color: #58a6ff; font-family: monospace; }
                .btn-back { display: inline-block; background: #21262d; color: #58a6ff; padding: 8px 16px; border-radius: 6px; text-decoration: none; margin-bottom: 20px; border: 1px solid #30363d; }
            </style>
        </head>
        <body>
            <div class="container">
                <a href="/" class="btn-back">← Zur Startseite</a>
                <div class="card">
                    <h1>🛡️ TITAN GATEWAY — Dashboard</h1>
                    <p>Anonymes Token aktiv (DSGVO-geschützt)</p>
                    <hr style="border: 0; border-top: 1px solid #30363d; margin: 16px 0;">
                    <h3>Raspi-Tunnel Traffic-Verbrauch</h3>
                    <p>${usedGB} GB von ${limitGB} GB genutzt (${percentUsed}%)</p>
                    <div class="progress-bg"><div class="progress-bar"></div></div>
                </div>

                <div class="card">
                    <h2>Dein Aktivitäts-Protokoll (Letzte 14 Tage)</h2>
                    <table>
                        <tr><th>Zeitpunkt</th><th>Methode</th><th>Ziel-URL</th><th>Größe</th></tr>
                        ${logs.map(l => `<tr><td>${l.timestamp}</td><td><span class="badge">${l.method}</span></td><td>${l.url}</td><td>${(l.bytes_transferred / 1024).toFixed(1)} KB</td></tr>`).join('')}
                    </table>
                </div>
            </div>
        </body>
        </html>
        `;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(html);
    }

    // 6. ADMIN DASHBOARD (/admin)
    if (req.url === '/admin' && req.method === 'GET') {
        const active = getValidSession(req);
        
        if (!active || !active.session.is_admin || active.user.email !== ADMIN_EMAIL) {
            res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8' });
            return res.end("🛡️ TITAN OS: Zugriff verweigert. Admin-Berechtigung erforderlich.");
        }

        const users = db.prepare('SELECT * FROM users').all();
        const allLogs = db.prepare('SELECT u.email, l.method, l.url, l.ip, l.bytes_transferred, l.timestamp FROM request_logs l JOIN users u ON l.user_id = u.id ORDER BY l.id DESC LIMIT 100').all();

        const html = `
        <!DOCTYPE html>
        <html lang="de">
        <head>
            <meta charset="UTF-8">
            <title>TITAN GATEWAY — Admin Control Center</title>
            <style>
                * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
                body { background: #0d1117; color: #c9d1d9; padding: 40px; }
                .container { max-width: 1100px; margin: 0 auto; }
                .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 24px; margin-bottom: 24px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
                h1, h2 { color: #f85149; margin-bottom: 16px; }
                table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 0.85rem; }
                th, td { text-align: left; padding: 10px; border-bottom: 1px solid #30363d; color: #8b949e; }
                th { color: #58a6ff; }
                .btn-ban { background: #da3633; color: white; border: none; padding: 4px 8px; border-radius: 4px; cursor: pointer; }
                .btn-unban { background: #238636; color: white; border: none; padding: 4px 8px; border-radius: 4px; cursor: pointer; }
                .btn-back { display: inline-block; background: #21262d; color: #58a6ff; padding: 8px 16px; border-radius: 6px; text-decoration: none; margin-bottom: 20px; border: 1px solid #30363d; }
            </style>
        </head>
        <body>
            <div class="container">
                <a href="/" class="btn-back">← Zur Startseite</a>
                <div class="card">
                    <h1>⚡ TITAN ADMIN CONTROL CENTER</h1>
                    <p>Admin: <strong>${active.user.email}</strong></p>
                    <hr style="border: 0; border-top: 1px solid #30363d; margin: 16px 0;">
                    <table>
                        <tr><th>ID</th><th>E-Mail</th><th>Traffic Genutzt</th><th>Status</th><th>Aktion</th></tr>
                        ${users.map(u => `
                            <tr>
                                <td>${u.id}</td>
                                <td>${u.email}</td>
                                <td>${(u.traffic_used / 1024 / 1024).toFixed(2)} MB</td>
                                <td>${u.is_banned ? '<span style="color:#f85149">Gesperrt</span>' : '<span style="color:#2ea043">Aktiv</span>'}</td>
                                <td>
                                    <form action="/admin/ban" method="POST" style="display:inline;">
                                        <input type="hidden" name="user_id" value="${u.id}">
                                        <input type="hidden" name="action" value="${u.is_banned ? 'unban' : 'ban'}">
                                        <button type="submit" class="${u.is_banned ? 'btn-unban' : 'btn-ban'}">${u.is_banned ? 'Entsperren' : 'Sperren'}</button>
                                    </form>
                                </td>
                            </tr>
                        `).join('')}
                    </table>
                </div>

                <div class="card">
                    <h2 style="color: #58a6ff;">Globales Live-Protokoll (Letzte 100 Requests)</h2>
                    <table>
                        <tr><th>Zeit</th><th>User</th><th>IP</th><th>Methode</th><th>Ziel</th><th>Größe</th></tr>
                        ${allLogs.map(l => `<tr><td>${l.timestamp}</td><td>${l.email}</td><td>${l.ip}</td><td>${l.method}</td><td>${l.url}</td><td>${(l.bytes_transferred / 1024).toFixed(1)} KB</td></tr>`).join('')}
                    </table>
                </div>
            </div>
        </body>
        </html>
        `;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(html);
    }

    if (req.url === '/admin/ban' && req.method === 'POST') {
        const active = getValidSession(req);
        if (!active || !active.session.is_admin || active.user.email !== ADMIN_EMAIL) {
            res.writeHead(403);
            return res.end("Unauthorized");
        }
        const data = await parsePostData(req);
        db.prepare('UPDATE users SET is_banned = ? WHERE id = ?').run(data.action === 'ban' ? 1 : 0, data.user_id);
        res.writeHead(302, { 'Location': '/admin' });
        return res.end();
    }

    // 7. PROXY CHECK: Nur wenn der Raspi-Modus aktiv ist und der titan_session Cookie existiert!
    const cookies = cookie.parse(req.headers.cookie || '');
    const active = getValidSession(req);
    
    if (active && active.session.is_raspi && cookies.titan_session) {
        if (active.user.traffic_used >= active.user.traffic_limit) {
            res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8' });
            return res.end(`🛡️ TITAN OS: Dein monatliches Traffic-Limit von ${Math.round(active.user.traffic_limit / 1024 / 1024 / 1024)} GB ist aufgebraucht.`);
        }
        req.titanUser = active.user;
        req.titanSession = active.session;
        return passToProxy(req, res);
    }

    // 8. Fallback: Startseite anzeigen (sichert Dashboard und Admin ab, kein Raspi-Proxy)
    renderStartPage(req, res, active ? active.user.email : null);

}).listen(PORT, () => {
    console.log(`TITAN Gateway läuft auf Port ${PORT}`);
});

function passToProxy(req, res) {
    proxy.web(req, res, { 
        target: NGROK_DOMAIN, 
        changeOrigin: true,
        headers: {
            "Authorization": authHeader,
            "ngrok-skip-browser-warning": "true",
            "X-Protected": "True",
            "Accept-Encoding": "identity" 
        }
    }, (err) => {
        console.error("Proxy-Fehler to ngrok:", err.message);
        res.writeHead(502, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end("🛡️ SHIELD TITAN OS: ngrok Tunnel nicht erreichbar.");
    });
}
