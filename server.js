import express from 'express';
import { createClient } from '@libsql/client';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// 환경변수에 붙여넣기로 끼어든 공백/줄바꿈을 제거 (Render 입력 실수 방지).
// URL/토큰에는 원래 공백이 없으므로 중간 공백까지 모두 제거한다.
const TURSO_URL = process.env.TURSO_URL?.replace(/\s+/g, '');
const TURSO_TOKEN = process.env.TURSO_TOKEN?.replace(/\s+/g, '');
const NAVER_CLIENT_ID = process.env.NAVER_CLIENT_ID?.trim();
const NAVER_CLIENT_SECRET = process.env.NAVER_CLIENT_SECRET?.trim();
// 선택: 콜백 URL을 강제 지정 (미설정 시 요청 호스트에서 자동 추론)
const NAVER_REDIRECT_URI = process.env.NAVER_REDIRECT_URI?.trim();
// 선택: 허용할 네이버 이메일 화이트리스트 (쉼표 구분, 비우면 모든 네이버 계정 허용)
const ALLOWED_EMAILS = (process.env.ALLOWED_NAVER_EMAILS || '')
  .split(',')
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);
// 선택: 기존 단일 데이터(id=1)를 이관받을 소유자 이메일.
// 이 계정이 처음 로그인할 때 레거시 플래너 데이터를 자기 계정으로 1회 복사한다.
const OWNER_NAVER_EMAIL = (process.env.OWNER_NAVER_EMAIL || '').trim().toLowerCase();
// 세션 쿠키 서명 키 (미설정 시 client secret에서 파생 — 가능하면 별도 지정 권장)
const SESSION_SECRET = (process.env.SESSION_SECRET || NAVER_CLIENT_SECRET || '').trim();
const PORT = process.env.PORT;

console.log(
  '[부팅] TURSO_URL set:', !!TURSO_URL,
  '| TOKEN len:', TURSO_TOKEN?.length || 0,
  '| NAVER_CLIENT_ID set:', !!NAVER_CLIENT_ID,
  '| ALLOWED_EMAILS:', ALLOWED_EMAILS.length || '(전체 허용)',
  '| OWNER:', OWNER_NAVER_EMAIL || '(이관 안 함)',
);

if (!TURSO_URL || !TURSO_TOKEN) {
  console.error('❌ TURSO_URL / TURSO_TOKEN 환경변수가 필요합니다. (.env 또는 Render 환경변수)');
  process.exit(1);
}
if (!NAVER_CLIENT_ID || !NAVER_CLIENT_SECRET) {
  console.error('❌ NAVER_CLIENT_ID / NAVER_CLIENT_SECRET 환경변수가 필요합니다.');
  process.exit(1);
}
if (!SESSION_SECRET) {
  console.error('❌ SESSION_SECRET(또는 NAVER_CLIENT_SECRET)이 필요합니다.');
  process.exit(1);
}

const db = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN });

async function initDb() {
  // 레거시: 단일 사용자 시절 데이터 (id=1). 이관 소스로만 남겨둔다.
  await db.execute(`
    CREATE TABLE IF NOT EXISTS planner_state (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      data TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `);
  // 멀티 사용자: 네이버 계정(uid)별로 플래너 상태를 한 행씩 저장
  await db.execute(`
    CREATE TABLE IF NOT EXISTS user_state (
      user_id TEXT PRIMARY KEY,
      email TEXT,
      name TEXT,
      data TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `);
}

// ── 세션: HMAC 서명된 쿠키 (외부 의존성 없음) ──
const SESSION_COOKIE = 'planner_session';
const OAUTH_STATE_COOKIE = 'planner_oauth_state';
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30일
const STATE_TTL_MS = 10 * 60 * 1000; // 10분

function signToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifyToken(token) {
  if (!token || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (!data.exp || data.exp < Date.now()) return null;
    return data;
  } catch {
    return null;
  }
}

function parseCookies(req) {
  const out = {};
  const header = req.headers.cookie;
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function baseUrl(req) {
  const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'http').split(',')[0].trim();
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  return `${proto}://${host}`;
}

function setCookie(res, name, value, maxAgeMs, secure) {
  const parts = [`${name}=${encodeURIComponent(value)}`, 'Path=/', 'HttpOnly', 'SameSite=Lax'];
  if (maxAgeMs != null) parts.push(`Max-Age=${Math.floor(maxAgeMs / 1000)}`);
  if (secure) parts.push('Secure');
  res.append('Set-Cookie', parts.join('; '));
}

function redirectUriFor(req) {
  return NAVER_REDIRECT_URI || `${baseUrl(req)}/auth/naver/callback`;
}

const app = express();
app.set('trust proxy', 1); // Render 등 프록시 뒤에서 https/host 정확히 인식
app.use(express.json({ limit: '5mb' }));

// 로그인 게이트: 미인증 상태로 메인 페이지에 들어오면 표지(로그인) 화면을 보여준다.
// (정적 파일 서빙보다 먼저 등록되어야 '/' · '/index.html' 을 가로챈다)
app.get(['/', '/index.html'], (req, res, next) => {
  const cookies = parseCookies(req);
  if (verifyToken(cookies[SESSION_COOKIE])) return next(); // 로그인됨 → 플래너(정적 파일)로
  res.sendFile(path.join(__dirname, 'login.html')); // 미로그인 → 표지 화면
});

// 정적 파일 (index.html 등) 서빙
app.use(express.static(__dirname, { extensions: ['html'] }));

// ── API 인증: 세션 쿠키 검사 ──
function auth(req, res, next) {
  const cookies = parseCookies(req);
  const session = verifyToken(cookies[SESSION_COOKIE]);
  if (session) {
    req.user = session;
    return next();
  }
  res.status(401).json({ error: 'unauthorized' });
}

// ── 네이버 OAuth 2.0 ──
// 1) 로그인 시작: 네이버 인증 페이지로 리다이렉트
app.get('/auth/naver', (req, res) => {
  const secure = baseUrl(req).startsWith('https');
  const state = crypto.randomBytes(16).toString('hex');
  setCookie(res, OAUTH_STATE_COOKIE, signToken({ state, exp: Date.now() + STATE_TTL_MS }), STATE_TTL_MS, secure);

  const url = new URL('https://nid.naver.com/oauth2.0/authorize');
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', NAVER_CLIENT_ID);
  url.searchParams.set('redirect_uri', redirectUriFor(req));
  url.searchParams.set('state', state);
  res.redirect(url.toString());
});

// 2) 콜백: code → access_token → 프로필 → 세션 쿠키 발급
app.get('/auth/naver/callback', async (req, res) => {
  const secure = baseUrl(req).startsWith('https');
  try {
    const { code, state } = req.query;
    const cookies = parseCookies(req);
    const saved = verifyToken(cookies[OAUTH_STATE_COOKIE]);
    setCookie(res, OAUTH_STATE_COOKIE, '', 0, secure); // state 쿠키 즉시 제거

    if (!code || !state || !saved || saved.state !== state) {
      return res.status(400).send('OAuth state 검증 실패. 다시 로그인해주세요.');
    }

    // 토큰 교환
    const tokenUrl = new URL('https://nid.naver.com/oauth2.0/token');
    tokenUrl.searchParams.set('grant_type', 'authorization_code');
    tokenUrl.searchParams.set('client_id', NAVER_CLIENT_ID);
    tokenUrl.searchParams.set('client_secret', NAVER_CLIENT_SECRET);
    tokenUrl.searchParams.set('code', String(code));
    tokenUrl.searchParams.set('state', String(state));
    tokenUrl.searchParams.set('redirect_uri', redirectUriFor(req));

    const usedRedirectUri = redirectUriFor(req);
    const tokenRes = await fetch(tokenUrl.toString());
    const tokenJson = await tokenRes.json();
    if (!tokenJson.access_token) {
      console.error('네이버 토큰 교환 실패', tokenJson, '| redirect_uri:', usedRedirectUri);
      return res
        .status(400)
        .type('text/plain; charset=utf-8')
        .send(
          '네이버 토큰 교환에 실패했습니다.\n\n' +
          `error: ${tokenJson.error || '(없음)'}\n` +
          `error_description: ${tokenJson.error_description || '(없음)'}\n` +
          `보낸 redirect_uri: ${usedRedirectUri}\n\n` +
          '※ 네이버 개발자센터에 등록된 Callback URL 과 위 redirect_uri 가 정확히 같아야 합니다.'
        );
    }

    // 프로필 조회
    const profileRes = await fetch('https://openapi.naver.com/v1/nid/me', {
      headers: { Authorization: `Bearer ${tokenJson.access_token}` },
    });
    const profileJson = await profileRes.json();
    if (profileJson.resultcode !== '00' || !profileJson.response) {
      console.error('네이버 프로필 조회 실패', profileJson);
      return res.status(400).send('네이버 프로필 조회에 실패했습니다.');
    }

    const p = profileJson.response; // { id, email, name, nickname, ... }
    const email = (p.email || '').toLowerCase();
    if (ALLOWED_EMAILS.length && !ALLOWED_EMAILS.includes(email)) {
      console.warn('허용되지 않은 계정 로그인 시도:', email || p.id);
      return res.status(403).send('이 플래너에 접근이 허용되지 않은 계정입니다.');
    }

    const session = {
      uid: p.id,
      name: p.name || p.nickname || '',
      email: p.email || '',
      exp: Date.now() + SESSION_TTL_MS,
    };
    setCookie(res, SESSION_COOKIE, signToken(session), SESSION_TTL_MS, secure);
    console.log('로그인:', session.email || session.uid);
    res.redirect('/');
  } catch (e) {
    console.error('OAuth 콜백 오류', e);
    res.status(500).send('로그인 처리 중 오류가 발생했습니다.');
  }
});

// 로그아웃: 세션 쿠키 제거
app.post('/auth/logout', (req, res) => {
  setCookie(res, SESSION_COOKIE, '', 0, baseUrl(req).startsWith('https'));
  res.json({ ok: true });
});

// 헬스체크 (인증 없음 — Render health check 용)
app.get('/healthz', (req, res) => res.json({ ok: true }));

// 현재 로그인 사용자 정보 (프론트 인증 확인용)
app.get('/api/me', auth, (req, res) => {
  res.json({ ok: true, user: { uid: req.user.uid, name: req.user.name, email: req.user.email } });
});

// 상태가 비어있는지 (할 일/일정이 하나도 없는지)
function isEmptyState(data) {
  if (!data) return true;
  const t = data.todos || {};
  const e = data.events || {};
  return Object.keys(t).length === 0 && Object.keys(e).length === 0;
}
function safeParse(s) {
  try { return JSON.parse(s); } catch { return null; }
}

// 상태 읽기 (로그인한 네이버 계정의 플래너만)
app.get('/api/state', auth, async (req, res) => {
  try {
    const uid = String(req.user.uid);
    const email = (req.user.email || '').toLowerCase();
    const r = await db.execute({
      sql: 'SELECT data, updated_at FROM user_state WHERE user_id = ?',
      args: [uid],
    });
    const myRow = r.rows[0];
    const myData = myRow ? safeParse(myRow.data) : null;

    // 소유자이고 내 플래너가 (없거나) 비어있으면 레거시(id=1) 데이터를 1회 이관한다.
    // 이관 후 레거시 행은 제거하여 다시 이관되지 않도록 한다(소유자가 직접 비웠을 때 되살아남 방지).
    if (OWNER_NAVER_EMAIL && email === OWNER_NAVER_EMAIL && isEmptyState(myData)) {
      const legacy = await db.execute('SELECT data, updated_at FROM planner_state WHERE id = 1');
      const legacyRow = legacy.rows[0];
      if (legacyRow && !isEmptyState(safeParse(legacyRow.data))) {
        const updatedAt = legacyRow.updated_at || new Date().toISOString();
        await db.batch([
          {
            sql: `INSERT INTO user_state (user_id, email, name, data, updated_at)
                  VALUES (?, ?, ?, ?, ?)
                  ON CONFLICT(user_id) DO UPDATE SET
                    data = excluded.data, updated_at = excluded.updated_at,
                    email = excluded.email, name = excluded.name`,
            args: [uid, req.user.email || '', req.user.name || '', legacyRow.data, updatedAt],
          },
          { sql: 'DELETE FROM planner_state WHERE id = 1', args: [] },
        ]);
        console.log('[이관] 레거시 플래너 데이터를 소유자에게 이관 완료:', email);
        const data = JSON.parse(legacyRow.data);
        return res.json({ ...data, updated_at: updatedAt });
      }
    }

    if (myRow) {
      const data = myData || { todos: {}, events: {}, colorLabels: {} };
      return res.json({ ...data, updated_at: myRow.updated_at });
    }
    // 신규 사용자 → 빈 플래너
    res.json({ todos: {}, events: {}, colorLabels: {}, updated_at: null });
  } catch (e) {
    console.error('GET /api/state 실패', e);
    res.status(500).json({ error: e.message });
  }
});

// 상태 저장 (로그인 계정별 전체 덮어쓰기, last-write-wins)
app.put('/api/state', auth, async (req, res) => {
  try {
    const uid = String(req.user.uid);
    const body = req.body || {};
    const payload = {
      todos: body.todos || {},
      events: body.events || {},
      colorLabels: body.colorLabels || {},
    };
    const now = new Date().toISOString();
    await db.execute({
      sql: `INSERT INTO user_state (user_id, email, name, data, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
              data = excluded.data,
              updated_at = excluded.updated_at,
              email = excluded.email,
              name = excluded.name`,
      args: [uid, req.user.email || '', req.user.name || '', JSON.stringify(payload), now],
    });
    res.json({ ok: true, updated_at: now });
  } catch (e) {
    console.error('PUT /api/state 실패', e);
    res.status(500).json({ error: e.message });
  }
});

const port = PORT || 3000;
initDb()
  .then(() => {
    app.listen(port, () => console.log(`✅ Planner 서버 실행: http://localhost:${port}`));
  })
  .catch((e) => {
    console.error('❌ DB 초기화 실패', e);
    process.exit(1);
  });
