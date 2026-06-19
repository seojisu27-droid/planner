# Planner

개인용 위클리/데일리 플래너. 데이터는 **Turso(클라우드 SQLite)**에 저장되어 어느 기기/브라우저에서 접속해도 동기화됩니다.

## 구조

- `index.html` — 프론트엔드 (단일 파일 SPA). 서버 API와 동기화하며 localStorage를 오프라인 캐시로 사용.
- `server.js` — Node/Express 백엔드. `index.html`을 서빙하고 `/api/state`로 Turso에 읽기/쓰기.
- 데이터는 비밀번호(`APP_PASSWORD`)로 보호됩니다.

## 로컬 실행

1. 의존성 설치
   ```
   npm install
   ```
2. `.env.example`을 복사해 `.env`를 만들고 값 채우기 (`TURSO_URL`, `TURSO_TOKEN`, `APP_PASSWORD`)
3. 실행
   ```
   npm run dev
   ```
   → http://localhost:3000 접속, 비밀번호 입력

### 기존 데이터 이전 (1회)

로컬 `todolist-data.json`을 Turso로 옮기려면:
```
npm run seed
```

## Render 배포 (Blueprint)

1. 이 저장소를 GitHub에 푸시
2. Render 대시보드 → **New → Blueprint** → 저장소 선택 (`render.yaml` 자동 인식)
3. 배포 중 환경변수 3개 입력:
   - `TURSO_URL`
   - `TURSO_TOKEN`
   - `APP_PASSWORD` (원하는 접근 비밀번호)
4. 배포 완료 후 발급된 URL 접속 → 비밀번호 입력

> 무료 플랜은 일정 시간 미사용 시 sleep 되어 첫 접속이 수십 초 걸릴 수 있습니다.

## 보안

- `.env`와 개인 데이터 파일(`todolist-data.json` 등)은 `.gitignore`로 제외됩니다.
- Turso 토큰이 노출된 적이 있다면 Turso 대시보드에서 재발급하세요.
