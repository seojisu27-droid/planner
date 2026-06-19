import express from 'express';
import { createClient } from '@libsql/client';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const { TURSO_URL, TURSO_TOKEN, APP_PASSWORD, PORT } = process.env;

if (!TURSO_URL || !TURSO_TOKEN) {
  console.error('❌ TURSO_URL / TURSO_TOKEN 환경변수가 필요합니다. (.env 또는 Render 환경변수)');
  process.exit(1);
}
if (!APP_PASSWORD) {
  console.warn('⚠️  APP_PASSWORD가 설정되지 않았습니다. API가 보호되지 않습니다! 배포 시 반드시 설정하세요.');
}

const db = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN });

// 단일 행(id=1)에 전체 상태를 JSON으로 저장
async function initDb() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS planner_state (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      data TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `);
}

const app = express();
app.use(express.json({ limit: '5mb' }));

// 정적 파일 (index.html 등) 서빙
app.use(express.static(__dirname, { extensions: ['html'] }));

// ── API 인증: x-app-password 헤더 검사 ──
function auth(req, res, next) {
  if (!APP_PASSWORD) return next(); // 비밀번호 미설정 시 통과 (개발용)
  if (req.get('x-app-password') === APP_PASSWORD) return next();
  res.status(401).json({ error: 'unauthorized' });
}

// 헬스체크 (인증 없음 — Render health check 용)
app.get('/healthz', (req, res) => res.json({ ok: true }));

// 비밀번호 확인용 (프론트에서 입력 검증)
app.get('/api/auth', auth, (req, res) => res.json({ ok: true }));

// 상태 읽기
app.get('/api/state', auth, async (req, res) => {
  try {
    const r = await db.execute('SELECT data, updated_at FROM planner_state WHERE id = 1');
    if (r.rows.length === 0) {
      return res.json({ todos: {}, events: {}, colorLabels: {}, updated_at: null });
    }
    const data = JSON.parse(r.rows[0].data);
    res.json({ ...data, updated_at: r.rows[0].updated_at });
  } catch (e) {
    console.error('GET /api/state 실패', e);
    res.status(500).json({ error: e.message });
  }
});

// 상태 저장 (전체 덮어쓰기, 단일 사용자 last-write-wins)
app.put('/api/state', auth, async (req, res) => {
  try {
    const body = req.body || {};
    const payload = {
      todos: body.todos || {},
      events: body.events || {},
      colorLabels: body.colorLabels || {},
    };
    const now = new Date().toISOString();
    await db.execute({
      sql: `INSERT INTO planner_state (id, data, updated_at)
            VALUES (1, ?, ?)
            ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`,
      args: [JSON.stringify(payload), now],
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
