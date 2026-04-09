const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const app = express();

app.use(cors());
app.use(express.json());

const dailyVisitors = new Map();
const coupangClicks = { total: 0, daily: new Map() };
const blockedIPs = new Map();
const requestCounts = new Map();
const securityLogs = [];
const RATE_LIMIT = 100;

function getToday() {
  return new Date().toISOString().slice(0, 10);
}

function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || req.connection.remoteAddress;
}

function getTime() {
  return new Date().toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' });
}

function hashPassword(pw) {
  return crypto.createHash('sha256').update(pw).digest('hex');
}

const sqlPatterns = /(\bSELECT\b|\bINSERT\b|\bDROP\b|\bUNION\b|--|;--|'--)/i;
const xssPatterns = /<script|javascript:|onerror=|onload=/i;

function sanitizeInput(str) {
  if (typeof str !== 'string') return str;
  return str
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

function detectMalicious(req) {
  const body = JSON.stringify(req.body || {});
  const query = JSON.stringify(req.query || {});
  const ua = req.headers['user-agent'] || '';
  if (sqlPatterns.test(body) || sqlPatterns.test(query)) return 'SQL Injection';
  if (xssPatterns.test(body) || xssPatterns.test(query)) return 'XSS';
  if (!ua || ua.includes('sqlmap') || ua.includes('nikto')) return 'Malicious Bot';
  return null;
}

app.use((req, res, next) => {
  const ip = getClientIP(req);
  const today = getToday();

  if (blockedIPs.has(ip)) return res.status(403).json({ error: 'Access denied' });

  const now = Date.now();
  const times = (requestCounts.get(ip) || []).filter(t => now - t < 60000);
  times.push(now);
  requestCounts.set(ip, times);
  if (times.length > RATE_LIMIT) {
    blockedIPs.set(ip, { reason: 'Rate Limit 초과', time: getTime() });
    securityLogs.push({ time: getTime(), ip, type: 'Rate Limit', detail: '1분에 100회 초과' });
    return res.status(429).json({ error: 'Too many requests' });
  }

  const threat = detectMalicious(req);
  if (threat) {
    blockedIPs.set(ip, { reason: threat, time: getTime() });
    securityLogs.push({ time: getTime(), ip, type: threat, detail: '악성 요청 감지' });
    return res.status(403).json({ error: 'Forbidden' });
  }

  if (req.method === 'GET' && req.path === '/') {
    if (!dailyVisitors.has(today)) dailyVisitors.set(today, new Set());
    dailyVisitors.get(today).add(ip);
  }

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');

  next();
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/security', (req, res) => {
  res.sendFile(path.join(__dirname, 'security_admin.html'));
});

app.post('/api/generate', async (req, res) => {
  try {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`,
      },
      body: JSON.stringify(req.body),
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/track/coupang', (req, res) => {
  const today = getToday();
  coupangClicks.total++;
  coupangClicks.daily.set(today, (coupangClicks.daily.get(today) || 0) + 1);
  res.json({ success: true });
});

app.get('/api/stats', (req, res) => {
  const today = getToday();
  const weekly = {};
  for (let i = 0; i < 7; i++) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    weekly[key] = dailyVisitors.get(key)?.size || 0;
  }
  res.json({
    today_visitors: dailyVisitors.get(today)?.size || 0,
    today_coupang_clicks: coupangClicks.daily.get(today) || 0,
    total_coupang_clicks: coupangClicks.total,
    blocked_ips: blockedIPs.size,
    weekly_visitors: weekly,
    status: 'ok'
  });
});

const ADMIN_PW_HASH = hashPassword(process.env.ADMIN_PASSWORD || 'admin1234');
const adminTokens = new Set();

app.post('/api/security/auth', (req, res) => {
  const { password } = req.body;
  if (!password) return res.json({ success: false });
  if (hashPassword(password) === ADMIN_PW_HASH) {
    const token = crypto.randomBytes(32).toString('hex');
    adminTokens.add(token);
    res.json({ success: true, token });
  } else {
    res.json({ success: false });
  }
});

function adminAuth(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!token || !adminTokens.has(token)) return res.status(403).json({ success: false });
  next();
}

app.get('/api/security/admin', adminAuth, (req, res) => {
  const todayRequests = [...requestCounts.values()].reduce((a, times) =>
    a + times.filter(t => Date.now() - t < 86400000).length, 0);
  res.json({
    success: true,
    blocked_count: blockedIPs.size,
    blocked_ips: [...blockedIPs.entries()].map(([ip, info]) => ({ ip, ...info })),
    security_logs: securityLogs.slice(-100),
    total_requests: todayRequests,
  });
});

app.post('/api/security/unblock', adminAuth, (req, res) => {
  const ip = sanitizeInput(req.body.ip);
  blockedIPs.delete(ip);
  securityLogs.push({ time: getTime(), ip, type: '차단 해제', detail: '관리자가 차단 해제' });
  res.json({ success: true });
});

app.post('/api/security/block', adminAuth, (req, res) => {
  const ip = sanitizeInput(req.body.ip);
  const reason = sanitizeInput(req.body.reason) || '수동 차단';
  blockedIPs.set(ip, { reason, time: getTime() });
  securityLogs.push({ time: getTime(), ip, type: '수동 차단', detail: reason });
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
