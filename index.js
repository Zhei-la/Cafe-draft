const express = require('express');
const cors = require('cors');
const path = require('path');
const app = express();

app.use(cors());
app.use(express.json());

// ── 방문자 추적 (IP 중복 제거) ──
const dailyVisitors = new Map();
const coupangClicks = { total: 0, daily: new Map() };
const blockedIPs = new Map(); // ip -> {reason, time}
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

const sqlPatterns = /(\bSELECT\b|\bINSERT\b|\bDROP\b|\bUNION\b|--|;--|'--)/i;
const xssPatterns = /<script|javascript:|onerror=|onload=/i;

function detectMalicious(req) {
  const body = JSON.stringify(req.body || {});
  const query = JSON.stringify(req.query || {});
  const ua = req.headers['user-agent'] || '';
  if (sqlPatterns.test(body) || sqlPatterns.test(query)) return 'SQL Injection';
  if (xssPatterns.test(body) || xssPatterns.test(query)) return 'XSS';
  if (!ua || ua.includes('sqlmap') || ua.includes('nikto')) return 'Malicious Bot';
  return null;
}

// ── 미들웨어 ──
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

  next();
});

// ── HTML 서빙 ──
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/security', (req, res) => {
  res.sendFile(path.join(__dirname, 'security_admin.html'));
});

// ── OpenAI 프록시 ──
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

// ── 쿠팡 클릭 추적 ──
app.post('/api/track/coupang', (req, res) => {
  const today = getToday();
  coupangClicks.total++;
  coupangClicks.daily.set(today, (coupangClicks.daily.get(today) || 0) + 1);
  res.json({ success: true });
});

// ── 통계 API ──
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

// ── 보안 관리 API ──
const ADMIN_PW = process.env.ADMIN_PASSWORD || 'admin1234';
const adminTokens = new Set();

app.post('/api/security/auth', (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PW) {
    const token = Math.random().toString(36).slice(2) + Date.now();
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
  const today = getToday();
  const todayRequests = [...requestCounts.values()].reduce((a, times) =>
    a + times.filter(t => Date.now() - t < 86400000).length, 0);
  res.json({
    success: true,
    blocked_count: blockedIPs.size,
    blocked_ips: [...blockedIPs.entries()].map(([ip, info]) => ({ ip, ...info })),
    security_logs: securityLogs,
    total_requests: todayRequests,
  });
});

app.post('/api/security/unblock', adminAuth, (req, res) => {
  const { ip } = req.body;
  blockedIPs.delete(ip);
  securityLogs.push({ time: getTime(), ip, type: '차단 해제', detail: '관리자가 차단 해제' });
  res.json({ success: true });
});

app.post('/api/security/block', adminAuth, (req, res) => {
  const { ip, reason } = req.body;
  blockedIPs.set(ip, { reason: reason || '수동 차단', time: getTime() });
  securityLogs.push({ time: getTime(), ip, type: '수동 차단', detail: reason || '관리자 수동 차단' });
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
