require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs').promises;
const path = require('path');
const morgan = require('morgan');

const app = express();
const PORT = process.env.PORT || 3000;

// Logging Setup
app.use(morgan('combined'));

// Sicherheitsbasics
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
}));

// CORS-Konfiguration
const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'];
const corsOptions = {
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Session Configuration für Admin-Panel
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback-secret-change-this',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 Stunden
    }
}));

// Static Files für Admin-Panel
app.use('/admin', express.static(path.join(__dirname, 'public')));

// Rate Limiting
const generateLimiter = rateLimit({
    windowMs: parseInt(process.env.GENERATE_RATE_LIMIT_WINDOW) || 900000,
    max: parseInt(process.env.GENERATE_RATE_LIMIT_MAX) || 10,
    message: 'Zu viele Key-Generierung-Versuche, bitte später erneut versuchen.',
    standardHeaders: true,
    legacyHeaders: false,
});

const validateLimiter = rateLimit({
    windowMs: parseInt(process.env.VALIDATE_RATE_LIMIT_WINDOW) || 60000,
    max: parseInt(process.env.VALIDATE_RATE_LIMIT_MAX) || 100,
    message: 'Zu viele Validierungs-Versuche, bitte später erneut versuchen.',
});

const deleteLimiter = rateLimit({
    windowMs: parseInt(process.env.DELETE_RATE_LIMIT_WINDOW) || 300000,
    max: parseInt(process.env.DELETE_RATE_LIMIT_MAX) || 20,
    message: 'Zu viele Lösch-Versuche, bitte später erneut versuchen.',
});

// Admin-Authentifizierung
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// File Paths
const KEYS_FILE = path.join(__dirname, 'data', 'keys.json');
const LOGS_FILE = path.join(__dirname, 'data', 'logs.json');
const BLACKLIST_FILE = path.join(__dirname, 'data', 'blacklist.json');

// Ensure data directory exists
async function ensureDataDirectory() {
    const dataDir = path.join(__dirname, 'data');
    try {
        await fs.access(dataDir);
    } catch {
        await fs.mkdir(dataDir, { recursive: true });
    }
}

// Storage Functions
async function loadJSON(filePath, defaultValue = {}) {
    try {
        const data = await fs.readFile(filePath, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        return defaultValue;
    }
}

async function saveJSON(filePath, data) {
    await fs.writeFile(filePath, JSON.stringify(data, null, 2));
}

// IP Helper Functions
function getClientIP(req) {
    return req.headers['x-forwarded-for'] ||
           req.connection.remoteAddress ||
           req.socket.remoteAddress ||
           (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
           'unknown';
}

async function isIPBlacklisted(ip) {
    const blacklist = await loadJSON(BLACKLIST_FILE, []);
    return blacklist.includes(ip);
}

async function logKeyInteraction(action, keyName, ip, success = true, details = {}) {
    const logs = await loadJSON(LOGS_FILE, []);
    const logEntry = {
        timestamp: new Date().toISOString(),
        action,
        keyName,
        ip,
        success,
        details,
        id: crypto.randomUUID()
    };
    
    logs.unshift(logEntry); // Neue Logs zuerst
    
    // Nur die letzten 1000 Logs behalten
    if (logs.length > 1000) {
        logs.splice(1000);
    }
    
    await saveJSON(LOGS_FILE, logs);
}

// Middleware
const requireAdminAuth = (req, res, next) => {
    const apiKey = req.headers['x-api-key'] || req.query.admin_key;
    if (!apiKey || apiKey !== ADMIN_API_KEY) {
        return res.status(401).json({ error: 'Unauthorized: Invalid admin credentials' });
    }
    next();
};

const requireAdminSession = (req, res, next) => {
    if (!req.session.isAdmin) {
        return res.status(401).json({ error: 'Admin login required' });
    }
    next();
};

const checkIPBlacklist = async (req, res, next) => {
    const ip = getClientIP(req);
    if (await isIPBlacklisted(ip)) {
        await logKeyInteraction('blocked_access', 'N/A', ip, false, { reason: 'IP blacklisted' });
        return res.status(403).json({ error: 'IP address is blacklisted' });
    }
    next();
};

// Key Generation Functions
function generateKritaKey() {
    const numbers1 = Math.floor(1000 + Math.random() * 9000);
    const numbers2 = Math.floor(1000 + Math.random() * 9000);
    return `krita-${numbers1}-${numbers2}`;
}

function calculateExpiration(duration) {
    const now = new Date();
    switch (duration) {
        case 'day':
            return new Date(now.getTime() + 24 * 60 * 60 * 1000);
        case 'week':
            return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
        case 'month':
            return new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
        case 'lifetime':
            return new Date('2099-12-31T23:59:59.999Z');
        default:
            throw new Error('Invalid duration');
    }
}

// API ENDPOINTS

// Admin Login
app.post('/admin/login', async (req, res) => {
    const { username, password } = req.body;
    const ip = getClientIP(req);
    
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        req.session.isAdmin = true;
        await logKeyInteraction('admin_login', 'N/A', ip, true);
        res.json({ success: true, message: 'Login erfolgreich' });
    } else {
        await logKeyInteraction('admin_login', 'N/A', ip, false, { reason: 'Invalid credentials' });
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// Admin Logout
app.post('/admin/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true, message: 'Logout erfolgreich' });
});

// Key generieren
app.get('/generate', generateLimiter, requireAdminAuth, async (req, res) => {
    try {
        const { day, week, month, lifetime } = req.query;
        const ip = getClientIP(req);
        let duration;
        
        if (day !== undefined) duration = 'day';
        else if (week !== undefined) duration = 'week';
        else if (month !== undefined) duration = 'month';
        else if (lifetime !== undefined) duration = 'lifetime';
        else {
            await logKeyInteraction('key_generate', 'N/A', ip, false, { reason: 'Invalid duration' });
            return res.status(400).json({ error: 'Invalid duration parameter' });
        }
        
        const keyName = generateKritaKey();
        const expiration = calculateExpiration(duration);
        const createdAt = new Date();
        
        const keys = await loadJSON(KEYS_FILE);
        keys[keyName] = {
            createdAt: createdAt.toISOString(),
            expiresAt: expiration.toISOString(),
            duration: duration,
            status: 'active',
            createdByIP: ip
        };
        
        await saveJSON(KEYS_FILE, keys);
        await logKeyInteraction('key_generate', keyName, ip, true, { duration });
        
        res.json({
            success: true,
            key: keyName,
            duration: duration,
            createdAt: createdAt.toISOString(),
            expiresAt: expiration.toISOString(),
            message: `Key erfolgreich generiert für ${duration}`
        });
        
    } catch (error) {
        console.error('Error generating key:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Key validieren
app.get('/validate', validateLimiter, checkIPBlacklist, async (req, res) => {
    try {
        const keyName = Object.keys(req.query)[0];
        const ip = getClientIP(req);
        
        if (!keyName || !keyName.startsWith('krita-')) {
            await logKeyInteraction('key_validate', keyName || 'invalid', ip, false, { reason: 'Invalid key format' });
            return res.json({ message: 'Key not Valid!' });
        }
        
        const keys = await loadJSON(KEYS_FILE);
        const keyData = keys[keyName];
        
        if (!keyData) {
            await logKeyInteraction('key_validate', keyName, ip, false, { reason: 'Key not found' });
            return res.json({ message: 'Key not Valid!' });
        }
        
        const now = new Date();
        const expirationDate = new Date(keyData.expiresAt);
        
        if (now > expirationDate) {
            await logKeyInteraction('key_validate', keyName, ip, false, { reason: 'Key expired' });
            return res.json({ message: 'Key expired' });
        }
        
        await logKeyInteraction('key_validate', keyName, ip, true);
        
        res.json({ 
            message: 'Key is Valid, welcome!',
            keyInfo: {
                duration: keyData.duration,
                createdAt: keyData.createdAt,
                expiresAt: keyData.expiresAt
            }
        });
        
    } catch (error) {
        console.error('Error validating key:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Key löschen
app.get('/delete', deleteLimiter, requireAdminAuth, async (req, res) => {
    try {
        const keyName = Object.keys(req.query).find(key => key !== 'admin_key');
        const ip = getClientIP(req);
        
        if (!keyName || !keyName.startsWith('krita-')) {
            await logKeyInteraction('key_delete', keyName || 'invalid', ip, false, { reason: 'Invalid key name' });
            return res.status(400).json({ error: 'Invalid key name' });
        }
        
        const keys = await loadJSON(KEYS_FILE);
        
        if (!keys[keyName]) {
            await logKeyInteraction('key_delete', keyName, ip, false, { reason: 'Key not found' });
            return res.status(404).json({ error: 'Key not found' });
        }
        
        delete keys[keyName];
        await saveJSON(KEYS_FILE, keys);
        await logKeyInteraction('key_delete', keyName, ip, true);
        
        res.json({
            success: true,
            message: `Key ${keyName} erfolgreich gelöscht`
        });
        
    } catch (error) {
        console.error('Error deleting key:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin API Endpoints
app.get('/admin/api/keys', requireAdminSession, async (req, res) => {
    try {
        const keys = await loadJSON(KEYS_FILE);
        const now = new Date();
        
        const keyStats = Object.entries(keys).map(([keyName, keyData]) => {
            const isExpired = new Date(keyData.expiresAt) < now;
            return {
                key: keyName,
                ...keyData,
                status: isExpired ? 'expired' : 'active'
            };
        });
        
        res.json({
            totalKeys: keyStats.length,
            activeKeys: keyStats.filter(k => k.status === 'active').length,
            expiredKeys: keyStats.filter(k => k.status === 'expired').length,
            keys: keyStats
        });
        
    } catch (error) {
        console.error('Error fetching keys:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/admin/api/logs', requireAdminSession, async (req, res) => {
    try {
        const logs = await loadJSON(LOGS_FILE, []);
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 50;
        const startIndex = (page - 1) * limit;
        const endIndex = startIndex + limit;
        
        res.json({
            logs: logs.slice(startIndex, endIndex),
            totalLogs: logs.length,
            currentPage: page,
            totalPages: Math.ceil(logs.length / limit)
        });
        
    } catch (error) {
        console.error('Error fetching logs:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/admin/api/blacklist', requireAdminSession, async (req, res) => {
    try {
        const { ip } = req.body;
        const adminIP = getClientIP(req);
        
        if (!ip) {
            return res.status(400).json({ error: 'IP address required' });
        }
        
        const blacklist = await loadJSON(BLACKLIST_FILE, []);
        
        if (!blacklist.includes(ip)) {
            blacklist.push(ip);
            await saveJSON(BLACKLIST_FILE, blacklist);
            
            // Keys von dieser IP löschen
            const keys = await loadJSON(KEYS_FILE);
            const keysToDelete = Object.entries(keys)
                .filter(([keyName, keyData]) => keyData.createdByIP === ip)
                .map(([keyName]) => keyName);
            
            keysToDelete.forEach(keyName => delete keys[keyName]);
            await saveJSON(KEYS_FILE, keys);
            
            await logKeyInteraction('ip_blacklist', 'N/A', adminIP, true, { 
                blacklistedIP: ip, 
                deletedKeys: keysToDelete.length 
            });
            
            res.json({ 
                success: true, 
                message: `IP ${ip} blacklisted, ${keysToDelete.length} keys deleted` 
            });
        } else {
            res.json({ success: false, message: 'IP already blacklisted' });
        }
        
    } catch (error) {
        console.error('Error blacklisting IP:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/admin/api/blacklist', requireAdminSession, async (req, res) => {
    try {
        const blacklist = await loadJSON(BLACKLIST_FILE, []);
        res.json({ blacklist });
    } catch (error) {
        console.error('Error fetching blacklist:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Health Check
app.get('/health', (req, res) => {
    res.json({ status: 'API läuft stabil', timestamp: new Date().toISOString() });
});

// Admin Panel Route
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Initialize
ensureDataDirectory().then(() => {
    app.listen(PORT, () => {
        console.log(`🔐 Sichere Key-Management API läuft auf Port ${PORT}`);
        console.log(`📊 Admin-Panel: http://localhost:${PORT}/admin`);
        console.log(`🔑 Admin API Key: ${ADMIN_API_KEY}`);
        console.log(`🛡️  Alle Sicherheitsfeatures aktiv`);
    });
});

module.exports = app;