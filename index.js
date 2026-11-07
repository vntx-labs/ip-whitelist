const http = require('http');
const httpProxy = require('http-proxy');
const axios = require('axios');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const cookie = require('cookie');
const { OAuth2Client } = require('google-auth-library');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

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

// --- DATENBANK SETUP (Im RAM) ---
const db = new Database(':memory:');

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password_hash TEXT,
        auth_provider TEXT DEFAULT 'local',
        traffic_used INTEGER DEFAULT 0,
        traffic_limit INTEGER DEFAULT 10737418240,
        is_banned INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER,
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

// DSGVO: Logs nach 14 Tagen löschen
setInterval(() => {
    db.prepare("DELETE FROM request_logs WHERE timestamp < datetime('now', '-14 days')").run();
}, 3600000);

const proxy = httpProxy.createProxyServer({});
let whitelist = [];

async function updateWhitelist() {
    try {
        const response = await axios.get(`${GIST_WHITELIST_URL}?nocache=${Date.now()}`, { timeout: 5000 });
        if (response.data) {
            const rawData = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
            whitelist = rawData.split('\n').map(ip => ip.replace('\r', '').replace(/"/g, '').trim()).filter(ip => ip.length > 0);
        }
    } catch (e) { console.error("[WHITELIST] Fehler:", e.message); }
}
setInterval(updateWhitelist, 300000);
setTimeout(updateWhitelist, 1000);

// DB Gist Sync
async function loadDatabaseFromGist() {
    try {
        const res = await axios.get(`${GIST_DB_URL}?nocache=${Date.now()}`, { headers: { Authorization: `Bearer ${GITHUB_TOKEN.trim()}` }, timeout: 5000 });
        if (res.data && res.data.users) {
            const insUser = db.prepare('INSERT OR REPLACE INTO users (id, email, password_hash, auth_provider, traffic_used, traffic_limit, is_banned, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
            for (const u of res.data.users || []) insUser.run(u.id, u.email, u.password_hash, u.auth_provider, u.traffic_used, u.traffic_limit, u.is_banned || 0, u.created_at);
            const insSes = db.prepare('INSERT OR REPLACE INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)');
            for (const s of res.data.sessions || []) insSes.run(s.token, s.user_id, s.expires_at);
        }
    } catch (e) { console.error("[DB] Ladefehler:", e.message); }
}
setTimeout(loadDatabaseFromGist, 2500);

async function syncDatabaseToGist() {
    try {
        const users = db.prepare('SELECT * FROM users').all();
        const sessions = db.prepare('SELECT * FROM sessions').all();
        await axios.patch(GIST_PATCH_API_URL, { files: { 'titan_users.json': { content: JSON.stringify({ users, sessions }, null, 2) } } }, {
            headers: { Authorization: `Bearer ${GITHUB_TOKEN.trim()}`, 'User-Agent': 'Titan-Gateway' }, timeout: 5000
        });
    } catch (e) { console.error("[DB Sync] Fehler:", e.message); }
}
setInterval(syncDatabaseToGist, 60000);

// Helper
function getSessionUser(req) {
    const cookies = cookie.parse(req.headers.cookie || '');
    const token = cookies.gateway_session;
    if (!token) return null;
    const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
    if (!session || new Date(session.expires_at) < new Date()) return null;
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
    if (!user || user.is_banned) return null;
    return user;
}

function parsePostData(req) {
    return new Promise((resolve) => {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            const params = new URLSearchParams(body);
            const data = {};
            for (const [k, v] of params.entries()) data[k] = v;
            resolve(data);
        });
    });
}

// --- SERVER & ROUTING ---
http.createServer(async (req, res) => {
    let clientIp = req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0].trim() : req.socket.remoteAddress;
    if (clientIp.startsWith('::ffff:')) clientIp = clientIp.replace('::ffff:', '');

    // 1. Whitelist: Sofort hart zum Raspi-Tunnel durchleiten
    if (whitelist.includes(clientIp)) {
        return passToProxy(req, res);
    }

    const user = getSessionUser(req);
    const urlPath = req.url.split('?')[0];

    // 2. Auth Endpoints
    if (urlPath === '/api/auth/login' && req.method === 'POST') {
        const { email, password } = await parsePostData(req);
        let u = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
        if (!u) {
            const hash = bcrypt.hashSync(password, 10);
            const r = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)').run(email, hash);
            u = db.prepare('SELECT * FROM users WHERE id = ?').get(r.lastInsertRowid);
        } else if (!bcrypt.compareSync(password, u.password_hash)) {
            res.writeHead(302, { 'Location': '/login.html?error=invalid_password' });
            return res.end();
        }
        const token = crypto.randomBytes(32).toString('hex');
        db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, u.id, new Date(Date.now() + 86400000).toISOString());
        res.setHeader('Set-Cookie', cookie.serialize('gateway_session', token, { httpOnly: true, path: '/', maxAge: 86400, sameSite: 'lax' }));
        res.writeHead(302, { 'Location': '/' });
        return res.end();
    }

    // --- LOGOUT ENDPUNKT ---
    if (urlPath === '/api/auth/logout' && (req.method === 'POST' || req.method === 'GET')) {
        const cookies = cookie.parse(req.headers.cookie || '');
        const token = cookies.gateway_session;
        
        // Session in der Datenbank löschen, falls vorhanden
        if (token) {
            db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
        }

        // Beide Cookies (Gateway & Raspi-Tunnel) sauber löschen
        res.setHeader('Set-Cookie', [
            cookie.serialize('gateway_session', '', { httpOnly: true, path: '/', maxAge: 0, sameSite: 'lax' }),
            cookie.serialize('gateway_time_hash', '', { httpOnly: true, path: '/', maxAge: 0, sameSite: 'lax' }),
            cookie.serialize('titan_session', '', { httpOnly: true, path: '/', maxAge: 0, sameSite: 'lax' })
        ]);

        res.writeHead(302, { 'Location': '/login.html' });
        return res.end();
    }

    if (urlPath === '/api/auth/google' && req.method === 'POST') {
        const { credential } = await parsePostData(req);
        try {
            const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
            const email = ticket.getPayload().email;
            let u = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
            if (!u) {
                const r = db.prepare('INSERT INTO users (email, auth_provider) VALUES (?, ?)').run(email, 'google');
                u = db.prepare('SELECT * FROM users WHERE id = ?').get(r.lastInsertRowid);
            }
            const token = crypto.randomBytes(32).toString('hex');
            db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, u.id, new Date(Date.now() + 86400000).toISOString());
            res.setHeader('Set-Cookie', cookie.serialize('gateway_session', token, { httpOnly: true, path: '/', maxAge: 86400, sameSite: 'lax' }));
            res.writeHead(302, { 'Location': '/' });
            return res.end();
        } catch (e) {
            res.writeHead(302, { 'Location': '/login.html?error=google_failed' });
            return res.end();
        }
    }

    // 3. Statische HTML-Seiten & Sicherheitswächter
    if (urlPath === '/' || urlPath === '/index.html') {
        if (!user) {
            res.writeHead(302, { 'Location': '/login.html' });
            return res.end();
        }
        return serveFile(res, 'public/index.html', { '{{USER_EMAIL}}': user.email, '{{IS_ADMIN}}': user.email === ADMIN_EMAIL ? 'true' : 'false' });
    }

    if (urlPath === '/login.html') {
        if (user) {
            res.writeHead(302, { 'Location': '/' });
            return res.end();
        }
        return serveFile(res, 'public/login.html', { '{{GOOGLE_CLIENT_ID}}': GOOGLE_CLIENT_ID });
    }

    if (urlPath === '/dashboard.html') {
        if (!user) {
            res.writeHead(302, { 'Location': '/login.html' });
            return res.end();
        }
        const usedGB = (user.traffic_used / (1024 * 1024 * 1024)).toFixed(2);
        const limitGB = (user.traffic_limit / (1024 * 1024 * 1024)).toFixed(2);
        const logs = db.prepare('SELECT method, url, timestamp FROM request_logs WHERE user_id = ? ORDER BY id DESC LIMIT 50').all();
        const logsHtml = logs.map(l => `<tr><td>${l.timestamp}</td><td>${l.method}</td><td>${l.url}</td></tr>`).join('');
        
        return serveFile(res, 'public/dashboard.html', { '{{USER_EMAIL}}': user.email, '{{USED_GB}}': usedGB, '{{LIMIT_GB}}': limitGB, '{{LOGS}}': logsHtml });
    }

    if (urlPath === '/admin.html') {
        if (!user || user.email !== ADMIN_EMAIL) {
            res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8' });
            return res.end("<h1>403 Forbidden</h1><p>Nur für den Administrator erlaubt.</p>");
        }
        const users = db.prepare('SELECT * FROM users').all();
        const usersHtml = users.map(u => `<tr><td>${u.id}</td><td>${u.email}</td><td>${u.is_banned ? 'Gesperrt' : 'Aktiv'}</td></tr>`).join('');
        return serveFile(res, 'public/admin.html', { '{{USERS}}': usersHtml });
    }

    // 4. DSGVO Endpoints (Berichtigung / Löschung)
    if (urlPath === '/api/dsgvo/delete' && user) {
        db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
        res.setHeader('Set-Cookie', cookie.serialize('gateway_session', '', { maxAge: 0, path: '/' }));
        res.writeHead(302, { 'Location': '/login.html' });
        return res.end();
    }

    // 5. Weiterleitung zum Raspi (Wird nur aufgerufen, wenn man aktiv auf "Weiter auf Titan" klickt)
    if (urlPath === '/tunnel') {
        if (!user) {
            res.writeHead(302, { 'Location': '/login.html' });
            return res.end();
        }
        // Aktiviere temporären titan_session Cookie für den Tunnel
        const titanToken = crypto.randomBytes(32).toString('hex');
        res.setHeader('Set-Cookie', [
            cookie.serialize('gateway_session', req.headers.cookie ? cookie.parse(req.headers.cookie).gateway_session || '' : '', { path: '/' }),
            cookie.serialize('titan_session', titanToken, { httpOnly: true, path: '/', maxAge: 3600, sameSite: 'lax' })
        ]);
        res.writeHead(302, { 'Location': '/' });
        return res.end();
    }

    // Fallback Proxy
    return passToProxy(req, res);

}).listen(PORT, () => {
    console.log(`TITAN Gateway läuft auf Port ${PORT}`);
});

function serveFile(res, filePath, replacements = {}) {
    const fullPath = path.join(__dirname, filePath);
    fs.readFile(fullPath, 'utf8', (err, content) => {
        if (err) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            return res.end('Datei nicht gefunden.');
        }
        for (const [key, val] of Object.entries(replacements)) {
            content = content.replaceAll(key, val);
        }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(content);
    });
}

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
        res.writeHead(502, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end("🛡️ SHIELD TITAN OS: ngrok Tunnel nicht erreichbar.");
    });
}
