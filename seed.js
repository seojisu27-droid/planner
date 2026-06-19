// 기존 로컬 데이터(todolist-data.json)를 Turso에 1회 이전(시드)합니다.
// 실행: npm run seed
import { createClient } from '@libsql/client';
import { readFileSync } from 'node:fs';

const { TURSO_URL, TURSO_TOKEN } = process.env;
if (!TURSO_URL || !TURSO_TOKEN) {
  console.error('TURSO_URL / TURSO_TOKEN 가 필요합니다.');
  process.exit(1);
}

const db = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN });

const raw = readFileSync(new URL('./todolist-data.json', import.meta.url), 'utf-8');
const parsed = JSON.parse(raw);
const payload = {
  todos: parsed.todos || {},
  events: parsed.events || {},
  colorLabels: parsed.colorLabels || {},
};

await db.execute(`
  CREATE TABLE IF NOT EXISTS planner_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    data TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )
`);

const now = new Date().toISOString();
await db.execute({
  sql: `INSERT INTO planner_state (id, data, updated_at) VALUES (1, ?, ?)
        ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`,
  args: [JSON.stringify(payload), now],
});

const days = new Set([...Object.keys(payload.todos), ...Object.keys(payload.events)]);
console.log(`✅ 시드 완료: ${days.size}일치 데이터 (할일 날짜 ${Object.keys(payload.todos).length}개, 일정 날짜 ${Object.keys(payload.events).length}개) → Turso 저장됨`);
process.exit(0);
