const http = require('http');
const httpProxy = require('http-proxy');
const axios = require('axios');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const cookie = require('cookie');
const { OAuth2Client } = require('google-auth-library');
const crypto = require('crypto');

// --- DATENBANK SETUP (Im RAM für Render, synchronisiert mit Gist) ---
const db = new Database(':memory:');

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password_hash TEXT,
        auth_provider TEXT DEFAULT 'local',
        traffic_used INTEGER DEFAULT 0, -- in Bytes
        traffic_limit INTEGER DEFAULT 10737418240, -- 10 GB Default in Bytes
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER,
        expires_at DATETIME,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
`);

// --- KONFIGURATION & CREDENTIALS ---
const GIST_WHITELIST_URL = "https://gist.githubusercontent.com/vntx-labs/8a31394fb00ddee15af6176caab86c2e/raw";
const GIST_DB_ID = process.env.GIST_DB_ID || "DEINE_PRIVATE_GIST_ID_FÜR_USERS";
const GITHUB_TOKEN = process.env.GITHUB_TOKEN; // Personal Access Token mit gist-Rechten

const NGROK_DOMAIN = "https://superrespectably-acquainted-jestine.ngrok-free.dev";
const USERNAME = "oI493HHYNPZXcxlAGClDrwmhID3xFJRbrWzeYBsMabgcqqDuZL";
const PASSWORD = "ql21AgNSJFHxh1aQAqy873ADT3MNExUurNDJTbP7vOf1zOtFJN";
const authHeader = 'Basic ' + Buffer.from(`${USERNAME}:${PASSWORD}`).toString('base64');

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "DEINE_GOOGLE_CLIENT_ID.apps.googleusercontent.com";
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

const proxy = httpProxy.createProxyServer({});

let whitelist = [];
let isUpdatingWhitelist = false;

// 1. IP-Whitelist alle 5 Minuten laden
async function updateWhitelist() {
    if (isUpdatingWhitelist) return;
    isUpdatingWhitelist = true;
    try {
        const response = await axios.get(`${GIST_WHITELIST_URL}?nocache=${Date.now()}`, { timeout: 5000 });
        if (response.data) {
            whitelist = response.data.split('\n')
                .map(ip => ip.replace('\r', '').trim())
                .filter(ip => ip.length > 0);
        }
    } catch (e) { 
        console.error("Fehler beim Laden der Whitelist:", e.message); 
    } finally {
        isUpdatingWhitelist = false;
    }
}
setInterval(updateWhitelist, 300000);
setTimeout(updateWhitelist, 2000);

// 2. DB-State aus GitHub Gist laden beim Start
async function loadDatabaseFromGist() {
    if (!GITHUB_TOKEN || !GIST_DB_ID) return;
    try {
        const res = await axios.get(`https://api.github.com/gists/${GIST_DB_ID}`, {
            headers: { Authorization: `token ${GITHUB_TOKEN}` }
        });
        const fileContent = res.data.files['titan_users.json'];
        if (fileContent && fileContent.content) {
            const data = JSON.parse(fileContent.content);
            const insertUser = db.prepare('INSERT OR REPLACE INTO users (id, email, password_hash, auth_provider, traffic_used, traffic_limit, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)');
            for (const u of data.users || []) {
                insertUser.run(u.id, u.email, u.password_hash, u.auth_provider, u.traffic_used, u.traffic_limit, u.created_at);
            }
            const insertSession = db.prepare('INSERT OR REPLACE INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)');
            for (const s of data.sessions || []) {
                insertSession.run(s.token, s.user_id, s.expires_at);
            }
            console.log(`[DB] ${data.users.length} Nutzer aus Gist geladen.`);
        }
    } catch (e) {
        console.error("[DB] Konnte Gist-DB nicht laden (initial leer?):", e.message);
    }
}
setTimeout(loadDatabaseFromGist, 3000);

// 3. DB-State alle 10 Sekunden asynchron ins Gist sichern (Traffic-Zähler & neue User)
async function syncDatabaseToGist() {
    if (!GITHUB_TOKEN || !GIST_DB_ID) return;
    try {
        const users = db.prepare('SELECT * FROM users').all();
        const sessions = db.prepare('SELECT * FROM sessions').all();
        const payload = JSON.stringify({ users, sessions }, null, 2);

        await axios.patch(`https://api.github.com/gists/${GIST_DB_ID}`, {
            files: {
                'titan_users.json': { content: payload }
            }
        }, {
            headers: { Authorization: `token ${GITHUB_TOKEN}` },
            timeout: 5000
        });
    } catch (e) {
        console.error("[DB Sync] Fehler beim Speichern ins Gist:", e.message);
    }
}
setInterval(syncDatabaseToGist, 10000); // Alle 10 Sekunden!

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

    // Traffic mitzählen für angemeldete Nutzer (Response Body Größe)
    if (req.titanUser && proxyRes.headers['content-length']) {
        const bytes = parseInt(proxyRes.headers['content-length'], 10) || 0;
        db.prepare('UPDATE users SET traffic_used = traffic_used + ? WHERE id = ?').run(bytes, req.titanUser.id);
    }
});

// --- HELPER HANDLERS ---
function getSessionUser(req) {
    const cookies = cookie.parse(req.headers.cookie || '');
    const token = cookies.titan_session;
    if (!token) return null;

    const session = db.prepare('SELECT user_id, expires_at FROM sessions WHERE token = ?').get(token);
    if (!session || new Date(session.expires_at) < new Date()) {
        if (session) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
        return null;
    }
    return db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
}

function createSession(res, userId) {
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 Tage
    db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, userId, expires.toISOString());
    
    res.setHeader('Set-Cookie', cookie.serialize('titan_session', token, {
        httpOnly: true, path: '/', maxAge: 30 * 24 * 60 * 60, sameSite: 'lax'
    }));
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

// --- LOGIN SEITE UI ---
function renderLoginPage(res, errorMessage = '') {
    const html = `
    <!DOCTYPE html>
    <html lang="de">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>TITAN GATEWAY — Login</title>
        <script src="https://accounts.google.com/gsi/client" async defer></script>
        <style>
            * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
            body { background: #0d1117; color: #c9d1d9; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
            .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 32px; width: 100%; max-width: 400px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
            .card h1 { font-size: 1.5rem; color: #58a6ff; margin-bottom: 8px; text-align: center; }
            .card p { font-size: 0.875rem; color: #8b949e; margin-bottom: 24px; text-align: center; }
            .error { background: rgba(248, 81, 73, 0.1); border: 1px solid #f85149; color: #f85149; padding: 10px; border-radius: 6px; font-size: 0.85rem; margin-bottom: 16px; text-align: center; }
            .form-group { margin-bottom: 16px; }
            label { display: block; font-size: 0.85rem; margin-bottom: 6px; color: #8b949e; }
            input[type="email"], input[type="password"] { width: 100%; padding: 10px 12px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-size: 0.9rem; }
            input:focus { border-color: #58a6ff; outline: none; }
            .btn { width: 100%; padding: 10px; background: #238636; border: none; border-radius: 6px; color: #fff; font-weight: 600; cursor: pointer; margin-top: 8px; font-size: 0.9rem; }
            .btn:hover { background: #2ea043; }
            .divider { display: flex; align-items: center; text-align: center; margin: 20px 0; color: #484f58; font-size: 0.8rem; }
            .divider::before, .divider::after { content: ''; flex: 1; border-bottom: 1px solid #30363d; }
            .divider::before { margin-right: .5em; } .divider::after { margin-left: .5em; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>🛡️ TITAN GATEWAY</h1>
            <p>10 GB Gratis-Kontingent aktiv. Bitte anmelden.</p>
            ${errorMessage ? `<div class="error">${errorMessage}</div>` : ''}
            
            <div id="g_id_onload" data-client_id="${GOOGLE_CLIENT_ID}" data-login_uri="/api/auth/google" data-auto_prompt="false"></div>
            <div class="g_id_signin" data-type="standard" data-size="large" data-theme="filled_black" data-text="sign_in_with" data-shape="rect" data-logo_alignment="left" data-width="336"></div>

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
                <button type="submit" class="btn">Anmelden / Registrieren</button>
            </form>
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

    // 1. IP-Whitelist-Check (Deine Admin-/Trusted-Geräte gehen sofort direkt durch)
    if (whitelist.includes(clientIp)) {
        return passToProxy(req, res);
    }

    // 2. Auth Endpoints
    if (req.url === '/api/auth/login' && req.method === 'POST') {
        const { email, password } = await parsePostData(req);
        if (!email || !password) return renderLoginPage(res, 'Bitte E-Mail und Passwort eingeben.');

        let user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
        if (!user) {
            const hash = bcrypt.hashSync(password, 10);
            const result = db.prepare('INSERT INTO users (email, password_hash, auth_provider) VALUES (?, ?, ?)').run(email, hash, 'local');
            user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
        } else if (user.password_hash) {
            if (!bcrypt.compareSync(password, user.password_hash)) return renderLoginPage(res, 'Ungültiges Passwort.');
        }

        createSession(res, user.id);
        res.writeHead(302, { 'Location': '/' });
        return res.end();
    }

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

            createSession(res, user.id);
            res.writeHead(302, { 'Location': '/' });
            return res.end();
        } catch (e) {
            return renderLoginPage(res, 'Google Login fehlgeschlagen.');
        }
    }

    // 3. Session & Traffic-Limit Check für externe Nutzer
    const user = getSessionUser(req);
    if (user) {
        if (user.traffic_used >= user.traffic_limit) {
            res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8' });
            return res.end(`🛡️ TITAN OS: Dein monatliches Traffic-Limit von ${Math.round(user.traffic_limit / 1024 / 1024 / 1024)} GB ist aufgebraucht.`);
        }
        req.titanUser = user; // Für den Traffic-Zähler im Proxy
        return passToProxy(req, res);
    }

    // 4. Nicht eingeloggt -> Responsive Login-Maske statt Fehlermeldung
    renderLoginPage(res);

}).listen(process.env.PORT || 3000, () => {
    console.log("TITAN Gateway läuft auf Port", process.env.PORT || 3000);
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
        console.error("Proxy-Fehler zu ngrok:", err.message);
        res.writeHead(502, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end("🛡️ TITAN OS: ngrok Tunnel nicht erreichbar.");
    });
}
