# Модель загроз SecureLab, ЛР 6 (DEL-01)

Рівень: **добрий («Добре»)**. Baseline 2-A.
Review-start commit: `013bf70b94d6706d5da8abeeabf22e74213e24ff` (`v0.5.0`), гілка `lab/6-hardening-review`.

## 1. Межі огляду

| Елемент | Що зафіксовано |
|---|---|
| Версія та середовище | review-start `013bf70`; Development (`dotnet run`, launch profile `http`, `http://localhost:5080`); production-like (`--no-launch-profile`, `ASPNETCORE_ENVIRONMENT=Production`, `-c Release`); SDK .NET 10 (`global.json` 10.0.100 / latestFeature); лише навчальні акаунти (alice, bob, morgan, admin); reset — `dotnet run --project src/SecureLab.Api -- --reset-database` тільки в Development |
| Компоненти в межах огляду | браузерний клієнт (`/`, `/auth-lab.html`, `/browser-lab.html`, `/session.html`); ASP.NET Core API (minimal APIs, Identity cookie, rate limiter, CORS, CSP); PostgreSQL 18 у Docker Compose (порт 127.0.0.1:54329); конфігурація (`appsettings*.json`, змінні середовища); console logs; NuGet restore; tracked files Git |
| Активи | облікові дані навчальних користувачів (password hash, не password); authentication cookie сеансу; власні інциденти Reporter (title, description, comments); право переходу `New → Triaged` (лише Analyst); внутрішні коментарі аналітика; audit-записи (`authorization.denied`, `audit.event`); конфігураційні секрети (connection string, `SeedUsers__Password`) |
| Суб'єкти | anonymous visitor; Reporter (alice, bob); Analyst (morgan); Administrator (admin — без опублікованих прав на Incident); сторонній сайт у тому самому браузері; локальний розробник |
| Entry points | `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/me`, `GET /api/auth/session-check`; `GET /api/incidents`, `GET /api/incidents/search`, `GET /api/incidents/severity-summary`, `GET /api/incidents/{id}`, `POST /api/incidents`, `PUT /api/incidents/{id}`, `DELETE /api/incidents/{id}`, `POST /api/incidents/{id}/triage`; `GET /api/incident-comments/{id}`; `GET /health`; статичні файли клієнта; завантаження конфігурації; `dotnet restore`; журнали |
| Наявні controls (ЛР 2–5) | серверна валідація DTO (ЛР 2), параметризовані запити EF Core (ЛР 2), Identity cookie HttpOnly/SameSite=Lax + login rate limiter 5/60 с (ЛР 3), авторизація за матрицею й query scoping (ЛР 4), safe DOM helper, CORS Development policy, CSP і headers (ЛР 5) |

## 2. Схема меж довіри

```
browser client (недовірене введення, автоматична auth cookie)
        │  HTTP (локальний development transport, http://localhost:5080)
        ▼
ASP.NET Core API (validation, authn/authz, antiforgery, rate limiting, logging)
        │  connection string / EF Core (параметризовані запити)
        ▼
PostgreSQL (дані застосунку, 127.0.0.1:54329)

repository + NuGet sources ──► restore / build (packages.lock.json)
environment configuration ────► API startup (ASPNETCORE_ENVIRONMENT, ConnectionStrings__SecureLab, SeedUsers__Password)
```

## 3. Межі довіри → очікувана властивість → конкретна перевірка

| Межа | Очікувана властивість | Наявна перевірка |
|---|---|---|
| browser → API | змінювальний запит із cookie без request token відхилено без зміни стану | REG-CSRF-01 (ЛР 6, етап 2) |
| browser → API | текст користувача не виконується як код | REG-XSS-01 (ЛР 5) |
| browser → API | сторонній origin не читає відповідь API | REG-CORS-01 (ЛР 5, повторно в ЛР 6) |
| browser → API | Reporter не отримує й не змінює чужий інцидент; ownerUserId із body ігнорується | A-03, A-04, A-08a (`Lab04AuthorizationTests`) |
| browser → API | неавтентифікований запит до protected route → 401 без redirect | A-01 (`Lab04AuthorizationTests`), A01 (`Lab03SecurityTests`) |
| browser → API | недопустиме input → 400 ValidationProblem | T-02 (`IncidentEndpointTests`), `GET /api/incidents?status=Unknown` |
| browser → API | масовий search / login обмежено квотою 429 | REG-RATE-01 (search, ЛР 6), login limiter (`Lab03SecurityTests`) |
| API → PostgreSQL | параметр пошуку не змінює структуру SQL | S-02 (`SearchMechanicsTests`, ЛР 2) |
| API → browser | клієнт не одержує stack trace, SQL чи connection string; є traceId | контрольована 500 у Production (етап 1, п. 5) |
| repository → build | tracked files не містять реальних credentials; навчальні значення класифіковано | `git grep` (етап 1, п. 3); `dotnet package list --vulnerable` (етап 3) |
| environment → configuration | у Production не діє Development-конфігурація, reset заборонено, OpenAPI не опубліковано | `Hosting environment: Production`, `--reset-database` → InvalidOperationException, `/openapi/v1.json` → 404 (етап 1, п. 4) |

## 4. Виключення

- Зовнішній penetration test, сторонні hosts і production deployment не тестувалися.
- Реальний TLS, сертифікат, HTTPS redirect і HSTS не перевірялися: штатний профіль лише HTTP на loopback.
- Уся історія Git, інші клони, fork і зовнішній CI не скануються; перевірено поточні tracked files.
- Distributed-сценарії (кілька instances, Redis) не входять до обраного рівня.
- Development-довідник `/scalar` (сторонній UI-package) не аналізується.
