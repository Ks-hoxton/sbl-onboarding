const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');
const { DatabaseSync } = require('node:sqlite');

const root = __dirname;
const dataDir = path.join(root, 'data');
const dbPath = path.join(dataDir, 'onboarding.sqlite');
const port = Number(process.env.PORT || 8787);
const defaultAdminEmail = process.env.ADMIN_EMAIL || 'admin@sbl.local';
const defaultAdminPassword = process.env.ADMIN_PASSWORD || 'admin123!';

fs.mkdirSync(dataDir, { recursive: true });
const db = new DatabaseSync(dbPath);

function initDb() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS admin_users (
      email TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      email TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS employees (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT,
      department TEXT,
      buddy TEXT,
      trainer TEXT,
      start_date TEXT,
      invite_token TEXT UNIQUE,
      first_seen_at TEXT,
      last_seen_at TEXT,
      status TEXT NOT NULL DEFAULT 'invited',
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS snapshots (
      employee_id TEXT PRIMARY KEY,
      state_json TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      employee_id TEXT NOT NULL,
      type TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      state_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS insights (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      employee_id TEXT NOT NULL,
      day INTEGER,
      mood TEXT,
      text TEXT,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS ratings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      employee_id TEXT NOT NULL,
      value INTEGER NOT NULL,
      label TEXT,
      created_at TEXT NOT NULL
    );
  `);

  const admin = db.prepare('SELECT email FROM admin_users WHERE email = ?').get(defaultAdminEmail);
  if (!admin) {
    db.prepare('INSERT INTO admin_users (email, name, password_hash, created_at) VALUES (?, ?, ?, ?)')
      .run(defaultAdminEmail, 'Администратор', hashPassword(defaultAdminPassword), new Date().toISOString());
  }
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = String(stored || '').split(':');
  if (!salt || !hash) return false;
  const actual = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(hash, 'hex');
  return expected.length === actual.length && crypto.timingSafeEqual(actual, expected);
}

function token(prefix = 'tok') {
  return `${prefix}_${crypto.randomBytes(18).toString('base64url')}`;
}

function send(res, status, body, type = 'application/json; charset=utf-8', headers = {}) {
  res.writeHead(status, {
    'Content-Type': type,
    'Cache-Control': 'no-store',
    ...headers
  });
  res.end(body);
}

function sendJson(res, status, data, headers = {}) {
  send(res, status, JSON.stringify(data), 'application/json; charset=utf-8', headers);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 1_000_000) {
        reject(new Error('Body too large'));
        req.destroy();
      }
    });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

function mime(file) {
  if (file.endsWith('.html')) return 'text/html; charset=utf-8';
  if (file.endsWith('.js')) return 'text/javascript; charset=utf-8';
  if (file.endsWith('.css')) return 'text/css; charset=utf-8';
  if (file.endsWith('.json')) return 'application/json; charset=utf-8';
  return 'application/octet-stream';
}

function parseCookies(req) {
  return Object.fromEntries(String(req.headers.cookie || '').split(';').filter(Boolean).map(part => {
    const [key, ...rest] = part.trim().split('=');
    return [key, decodeURIComponent(rest.join('='))];
  }));
}

function getAdmin(req) {
  const tokenValue = parseCookies(req).sbl_admin_session;
  if (!tokenValue) return null;
  const row = db.prepare(`
    SELECT s.email, a.name
    FROM sessions s
    JOIN admin_users a ON a.email = s.email
    WHERE s.token = ? AND s.expires_at > ?
  `).get(tokenValue, new Date().toISOString());
  return row || null;
}

function requireAdmin(req, res) {
  const admin = getAdmin(req);
  if (!admin) {
    sendJson(res, 401, { ok: false, error: 'Unauthorized' });
    return null;
  }
  return admin;
}

function normalizeEmployeeName(value) {
  const name = String(value || '').trim();
  if (!name) return '';
  if (
    name === 'preview' ||
    /^emp[-_]/i.test(name) ||
    /^invite[_-]/i.test(name) ||
    /скопировать/i.test(name)
  ) return '';
  return name;
}

function clampInt(value, min, max) {
  const num = Number(value);
  if (!Number.isFinite(num)) return min;
  return Math.min(max, Math.max(min, Math.round(num)));
}

function sanitizeProgressState(state = {}) {
  const dayLabels = ['Welcome', 'День 1', 'День 2', 'День 3', 'День 4', 'День 5', 'День 6'];
  const levelLabels = new Set([
    'Уровень 1 — Кандидат',
    'Уровень 2 — Стажёр',
    'Уровень 3 — Специалист',
    'Уровень 4 — Практик',
    'Гуру SBL'
  ]);
  const currentDay = clampInt(state.currentDay, 0, 6);
  const dayPercents = Array.isArray(state.dayPercents)
    ? state.dayPercents.slice(0, 7).map(value => clampInt(value, 0, 100))
    : [];
  while (dayPercents.length < 7) dayPercents.push(0);

  const checklistDone = clampInt(state.checklist?.done, 0, 999);
  const checklistTotal = clampInt(state.checklist?.total, checklistDone, 999);
  const materialsOpened = clampInt(state.materials?.opened, 0, 999);
  const materialsTotal = clampInt(state.materials?.total, materialsOpened, 999);
  const quizzesDone = clampInt(state.quizzes?.done, 0, 999);
  const quizzesTotal = clampInt(state.quizzes?.total, quizzesDone, 999);
  const bitrixDone = clampInt(state.bitrixTest?.done, 0, 999);
  const bitrixTotal = clampInt(state.bitrixTest?.total, bitrixDone, 999);
  const completedDaysCount = clampInt(state.completedDaysCount, 0, 7);
  const totalProgress = clampInt(state.totalProgress, 0, 100);
  const rating = clampInt(state.rating, 0, 5);
  const level = levelLabels.has(state.level) ? state.level : 'Уровень 1 — Кандидат';
  const rawUi = state.ui && typeof state.ui === 'object' ? state.ui : {};
  const uniqStrings = values => Array.isArray(values)
    ? values.map(value => String(value || '').trim()).filter(Boolean).filter((value, index, arr) => arr.indexOf(value) === index)
    : [];
  const ui = {
    checks: uniqStrings(rawUi.checks),
    openedMaterials: uniqStrings(rawUi.openedMaterials),
    learnedCards: uniqStrings(rawUi.learnedCards),
    quizDone: uniqStrings(rawUi.quizDone),
    finalQuizDone: uniqStrings(rawUi.finalQuizDone),
    day1RatingVal: clampInt(rawUi.day1RatingVal, 0, 5),
    ratingVal: clampInt(rawUi.ratingVal, 0, 5),
    welcomePathSent: !!rawUi.welcomePathSent,
    day1ReflectionSent: !!rawUi.day1ReflectionSent,
    day3CreativeSent: !!rawUi.day3CreativeSent,
    day4InsightSent: !!rawUi.day4InsightSent,
    finalFeedbackSent: !!rawUi.finalFeedbackSent,
    finalMetricRatings: {
      trainer: clampInt(rawUi.finalMetricRatings?.trainer, 0, 5),
      vk: clampInt(rawUi.finalMetricRatings?.vk, 0, 5),
      materials: clampInt(rawUi.finalMetricRatings?.materials, 0, 5),
      comfort: clampInt(rawUi.finalMetricRatings?.comfort, 0, 5)
    },
    textFields: {
      welcomePathText: String(rawUi.textFields?.welcomePathText || ''),
      day1Expectations: String(rawUi.textFields?.day1Expectations || ''),
      day1Questions: String(rawUi.textFields?.day1Questions || ''),
      day3CreativeText: String(rawUi.textFields?.day3CreativeText || ''),
      day4InsightText: String(rawUi.textFields?.day4InsightText || ''),
      finalTrainer: String(rawUi.textFields?.finalTrainer || ''),
      finalVk: String(rawUi.textFields?.finalVk || ''),
      finalWishes: String(rawUi.textFields?.finalWishes || '')
    }
  };

  return {
    currentDay,
    currentDayLabel: dayLabels[currentDay],
    maxUnlockedDay: clampInt(state.maxUnlockedDay, 0, 6),
    completedDays: Array.isArray(state.completedDays)
      ? state.completedDays.map(value => clampInt(value, 0, 6)).filter((value, index, arr) => arr.indexOf(value) === index).sort((a, b) => a - b)
      : [],
    completedDaysCount,
    totalDays: 7,
    dayPercents,
    totalProgress,
    checklist: { done: checklistDone, total: checklistTotal },
    materials: { opened: materialsOpened, total: materialsTotal },
    quizzes: { done: quizzesDone, total: quizzesTotal },
    bitrixTest: { done: bitrixDone, total: bitrixTotal },
    rating,
    level,
    ui
  };
}

function resolveEmployee(body, now) {
  const inviteToken = String(body.inviteToken || '').trim();
  const incomingName = normalizeEmployeeName(body.employeeName);
  let employee = inviteToken
    ? db.prepare('SELECT * FROM employees WHERE invite_token = ?').get(inviteToken)
    : null;

  const fallbackId = String(body.employeeId || 'unknown');
  if (!employee) {
    employee = db.prepare('SELECT * FROM employees WHERE id = ?').get(fallbackId);
  }
  if (!employee) {
    return null;
  }

  const firstSeen = employee.first_seen_at || now;
  const nextName = employee.name && employee.name.trim()
    ? employee.name
    : (incomingName || employee.name);
  db.prepare(`
    UPDATE employees
    SET name = COALESCE(NULLIF(?, ''), name),
        first_seen_at = ?,
        last_seen_at = ?,
        status = 'active'
    WHERE id = ?
  `).run(nextName, firstSeen, now, employee.id);
  return db.prepare('SELECT * FROM employees WHERE id = ?').get(employee.id);
}

function publicEmployee(employee) {
  const snapshot = db.prepare('SELECT state_json, updated_at FROM snapshots WHERE employee_id = ?').get(employee.id);
  const state = snapshot ? sanitizeProgressState(JSON.parse(snapshot.state_json)) : {};
  const insights = db.prepare('SELECT day, mood, text, created_at AS at FROM insights WHERE employee_id = ? ORDER BY created_at DESC LIMIT 100').all(employee.id);
  const ratings = db.prepare('SELECT value, label, created_at AS at FROM ratings WHERE employee_id = ? ORDER BY created_at DESC LIMIT 50').all(employee.id);
  const overallRatingEntry = ratings.find(item => String(item.label || '').startsWith('Онбординг:'));
  const events = db.prepare('SELECT type, payload_json, created_at AS at FROM events WHERE employee_id = ? ORDER BY created_at DESC LIMIT 20').all(employee.id)
    .map(event => ({ at: event.at, type: event.type, payload: JSON.parse(event.payload_json) }));
  const firstSeen = employee.first_seen_at ? new Date(employee.first_seen_at) : null;
  const daysSinceFirstSeen = firstSeen
    ? Math.max(0, Math.floor((Date.now() - firstSeen.getTime()) / 86400000))
    : 0;

  return {
    id: employee.id,
    name: employee.name,
    email: employee.email || '',
    department: employee.department || '',
    buddy: employee.buddy || '',
    trainer: employee.trainer || '',
    startDate: employee.start_date || '',
    inviteToken: employee.invite_token,
    inviteUrl: `/invite/${employee.invite_token}`,
    firstSeen: employee.first_seen_at,
    lastSeen: employee.last_seen_at,
    daysSinceFirstSeen,
    currentDay: state.currentDay || 0,
    currentDayLabel: state.currentDayLabel || 'Welcome',
    completedDaysCount: state.completedDaysCount || 0,
    totalDays: state.totalDays || 7,
    totalProgress: state.totalProgress || 0,
    dayPercents: state.dayPercents || [],
    checklist: state.checklist || { done: 0, total: 0 },
    materials: state.materials || { opened: 0, total: 0 },
    quizzes: state.quizzes || { done: 0, total: 0 },
    bitrixTest: state.bitrixTest || { done: 0, total: 0 },
    rating: overallRatingEntry?.value || state.rating || 0,
    overallRating: overallRatingEntry?.value || state.rating || 0,
    level: state.level || 'Уровень 1 — Кандидат',
    insights,
    ratings,
    events
  };
}

function absoluteInvite(req, inviteToken) {
  const proto = req.headers['x-forwarded-proto'] || 'http';
  return `${proto}://${req.headers.host}/invite/${inviteToken}`;
}

async function handleApi(req, res, url) {
  if (req.method === 'POST' && url.pathname === '/api/admin/login') {
    const body = JSON.parse(await readBody(req) || '{}');
    const admin = db.prepare('SELECT * FROM admin_users WHERE email = ?').get(String(body.email || '').trim());
    if (!admin || !verifyPassword(String(body.password || ''), admin.password_hash)) {
      sendJson(res, 401, { ok: false, error: 'Неверный email или пароль' });
      return true;
    }
    const sessionToken = token('sess');
    const now = new Date();
    const expires = new Date(now.getTime() + 1000 * 60 * 60 * 24 * 14).toISOString();
    db.prepare('INSERT INTO sessions (token, email, expires_at, created_at) VALUES (?, ?, ?, ?)')
      .run(sessionToken, admin.email, expires, now.toISOString());
    sendJson(res, 200, { ok: true, admin: { email: admin.email, name: admin.name } }, {
      'Set-Cookie': `sbl_admin_session=${encodeURIComponent(sessionToken)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${60 * 60 * 24 * 14}`
    });
    return true;
  }

  if (req.method === 'POST' && url.pathname === '/api/admin/logout') {
    const sessionToken = parseCookies(req).sbl_admin_session;
    if (sessionToken) db.prepare('DELETE FROM sessions WHERE token = ?').run(sessionToken);
    sendJson(res, 200, { ok: true }, {
      'Set-Cookie': 'sbl_admin_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'
    });
    return true;
  }

  if (req.method === 'GET' && url.pathname === '/api/admin/me') {
    const admin = getAdmin(req);
    sendJson(res, 200, { ok: !!admin, admin });
    return true;
  }

  if (req.method === 'POST' && url.pathname === '/api/event') {
    try {
      const body = JSON.parse(await readBody(req) || '{}');
      const now = new Date().toISOString();
      const employee = resolveEmployee(body, now);
      if (!employee) {
        sendJson(res, 404, { ok: false, error: 'Employee not found' });
        return true;
      }
      const eventType = body.type || 'event';
      const payload = body.payload || {};
      const state = sanitizeProgressState(body.state || {});

      db.prepare('INSERT INTO events (employee_id, type, payload_json, state_json, created_at) VALUES (?, ?, ?, ?, ?)')
        .run(employee.id, eventType, JSON.stringify(payload), JSON.stringify(state), now);
      db.prepare(`
        INSERT INTO snapshots (employee_id, state_json, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(employee_id) DO UPDATE SET state_json = excluded.state_json, updated_at = excluded.updated_at
      `).run(employee.id, JSON.stringify(state), now);

      if (eventType === 'insight') {
        db.prepare('INSERT INTO insights (employee_id, day, mood, text, created_at) VALUES (?, ?, ?, ?, ?)')
          .run(employee.id, payload.day ?? null, payload.mood || '', payload.text || '', now);
      }
      if (eventType === 'rating') {
        db.prepare('INSERT INTO ratings (employee_id, value, label, created_at) VALUES (?, ?, ?, ?)')
          .run(employee.id, Number(payload.value || 0), payload.label || '', now);
      }

      sendJson(res, 200, { ok: true, employeeId: employee.id });
    } catch (error) {
      sendJson(res, 400, { ok: false, error: error.message });
    }
    return true;
  }

  if (req.method === 'GET' && url.pathname === '/api/employee-state') {
    const inviteToken = String(url.searchParams.get('inviteToken') || '').trim();
    const employeeId = String(url.searchParams.get('employeeId') || '').trim();
    let employee = inviteToken
      ? db.prepare('SELECT * FROM employees WHERE invite_token = ?').get(inviteToken)
      : null;
    if (!employee && employeeId) {
      employee = db.prepare('SELECT * FROM employees WHERE id = ?').get(employeeId);
    }
    if (!employee) {
      sendJson(res, 404, { ok: false, error: 'Employee not found' });
      return true;
    }
    const snapshot = db.prepare('SELECT state_json, updated_at FROM snapshots WHERE employee_id = ?').get(employee.id);
    const state = snapshot ? sanitizeProgressState(JSON.parse(snapshot.state_json)) : null;
    sendJson(res, 200, {
      ok: true,
      employee: {
        id: employee.id,
        name: employee.name,
        inviteToken: employee.invite_token,
        firstSeen: employee.first_seen_at,
        lastSeen: employee.last_seen_at
      },
      state
    });
    return true;
  }

  if (url.pathname.startsWith('/api/admin')) {
    if (!requireAdmin(req, res)) return true;
  }

  if (req.method === 'GET' && url.pathname === '/api/admin') {
    const employees = db.prepare('SELECT * FROM employees ORDER BY COALESCE(last_seen_at, created_at) DESC').all()
      .map(publicEmployee);
    const totals = {
      employees: employees.length,
      activeToday: employees.filter(e => e.lastSeen && Date.now() - new Date(e.lastSeen).getTime() < 86400000).length,
      completed: employees.filter(e => e.completedDaysCount >= e.totalDays).length,
      averageProgress: employees.length
        ? Math.round(employees.reduce((sum, e) => sum + (e.totalProgress || 0), 0) / employees.length)
        : 0,
      insights: employees.reduce((sum, e) => sum + e.insights.length, 0)
    };
    sendJson(res, 200, { totals, employees });
    return true;
  }

  if (req.method === 'POST' && url.pathname === '/api/admin/employees') {
    const body = JSON.parse(await readBody(req) || '{}');
    const now = new Date().toISOString();
    const name = String(body.name || '').trim();
    if (!name) {
      sendJson(res, 400, { ok: false, error: 'Укажите имя сотрудника' });
      return true;
    }
    const inviteToken = token('invite');
    const id = `emp_${crypto.randomBytes(6).toString('hex')}`;
    db.prepare(`
      INSERT INTO employees (id, name, email, department, buddy, trainer, start_date, invite_token, status, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'invited', ?)
    `).run(
      id,
      name,
      String(body.email || '').trim(),
      String(body.department || '').trim(),
      String(body.buddy || '').trim(),
      String(body.trainer || '').trim(),
      String(body.startDate || '').trim(),
      inviteToken,
      now
    );
    sendJson(res, 200, { ok: true, employee: publicEmployee(db.prepare('SELECT * FROM employees WHERE id = ?').get(id)), inviteUrl: absoluteInvite(req, inviteToken) });
    return true;
  }

  if (req.method === 'DELETE' && url.pathname.startsWith('/api/admin/employees/')) {
    const id = decodeURIComponent(url.pathname.split('/').pop() || '');
    const employee = db.prepare('SELECT id FROM employees WHERE id = ?').get(id);
    if (!employee) {
      sendJson(res, 404, { ok: false, error: 'Сотрудник не найден' });
      return true;
    }
    db.exec('BEGIN');
    try {
      db.prepare('DELETE FROM events WHERE employee_id = ?').run(id);
      db.prepare('DELETE FROM insights WHERE employee_id = ?').run(id);
      db.prepare('DELETE FROM ratings WHERE employee_id = ?').run(id);
      db.prepare('DELETE FROM snapshots WHERE employee_id = ?').run(id);
      db.prepare('DELETE FROM employees WHERE id = ?').run(id);
      db.exec('COMMIT');
      sendJson(res, 200, { ok: true });
    } catch (error) {
      db.exec('ROLLBACK');
      sendJson(res, 500, { ok: false, error: error.message });
    }
    return true;
  }

  return false;
}

function serveFile(res, filePath) {
  fs.readFile(filePath, (error, content) => {
    if (error) {
      send(res, 404, 'Not found', 'text/plain; charset=utf-8');
      return;
    }
    send(res, 200, content, mime(filePath));
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname.startsWith('/api/')) {
    if (await handleApi(req, res, url)) return;
    sendJson(res, 404, { ok: false, error: 'Not found' });
    return;
  }

  if (url.pathname === '/admin') {
    serveFile(res, path.join(root, 'admin.html'));
    return;
  }

  if (url.pathname.startsWith('/invite/')) {
    serveFile(res, path.join(root, 'index.html'));
    return;
  }

  if (url.pathname === '/' || url.pathname === '/index.html') {
    serveFile(res, path.join(root, 'index.html'));
    return;
  }

  const safePath = path.normalize(url.pathname).replace(/^(\.\.[/\\])+/, '');
  serveFile(res, path.join(root, safePath));
});

initDb();
const host = process.env.HOST || '0.0.0.0';

server.listen(port, host, () => {
  console.log(`SBL onboarding is running: http://localhost:${port}`);
  console.log(`Admin dashboard: http://localhost:${port}/admin`);
  console.log(`Default admin: ${defaultAdminEmail} / ${defaultAdminPassword}`);
});
