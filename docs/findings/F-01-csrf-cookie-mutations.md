# F-01. Змінювальні маршрути з cookie-автентифікацією не перевіряли antiforgery token

**Статус:** Fixed
**Актив:** право автентифікованого користувача змінювати власні інциденти, статус інциденту (triage), чинність сеансу (logout).
**Компонент:** `src/SecureLab.Api/Presentation/Endpoints/IncidentEndpoints.cs` (POST, PUT, DELETE, triage), `src/SecureLab.Api/Scaffolding/Lab03Identity.cs` (logout), браузерний клієнт.
**Пріоритет:** високий. Impact — несанкціонована зміна або видалення даних і примусовий вихід від імені користувача; likelihood — середня: потрібні активний сеанс жертви та сторінка зловмисника в тому самому браузері (SameSite=Lax зменшує, але не усуває ризик для same-site сценаріїв і не є контрактом захисту).

## Відтворення (до виправлення, review-start `013bf70`)

1. Development, reset, вхід як alice на `/auth-lab.html`.
2. У Console сторінки того самого origin: `fetch("/api/incidents", { method: "POST", headers: { "Content-Type": "application/json" }, body: … })` **без** заголовка request token.
3. Фактично: **201 Created** — запис створено лише на підставі автоматично надісланої auth cookie.

## Першопричина

Сервер приймав будь-який state-changing запит, якщо браузер автоматично додав authentication cookie. Не було механізму, що відрізняє свідомий запит власного клієнта від запиту, ініційованого іншою сторінкою. `UseAntiforgery()` не захищає JSON-endpoints і DELETE автоматично; CORS і SameSite не є заміною.

## Виправлення

- `Security/AntiforgeryEndpoints.cs`: `AddAntiforgery` (header `X-CSRF-TOKEN`, cookie `SecureLab.Antiforgery`, HttpOnly, SameSite=Strict); маршрут `GET /api/auth/csrf-token` (лише після входу, `Cache-Control: no-cache, no-store`).
- `Security/AntiforgeryFilter.cs`: єдине місце `ValidateRequestAsync`; `AntiforgeryValidationException` → **400** Problem Details до виконання обробника.
- Фільтр підключено до SC-01…SC-05 (create, update, delete, triage, logout). Login/register — окреме рішення (див. `security-review.md`, 8.1).
- Клієнт: `Client/csrf-helper.js` (lazy token у пам'яті, лише same-origin, лише POST/PUT/PATCH/DELETE, `reset()` після login/logout) на `auth-lab`, `browser-lab`, `session`.

## Retest (REG-CSRF-01)

Та сама сесія alice, без токена: POST → 400, кількість записів з унікальною назвою 0 → 0; PUT → 400, title/description незмінні; DELETE → 400, ресурс лишився (200); logout → 400, `/api/me` → 200. Morgan: triage без токена → 400, статус New.
Автоматично: `Lab06CsrfTests` (3 тести) — PASS.

## Positive regression

З валідною парою: POST → 201 і запис з'явився (1); logout → 204, `/api/me` → 401; triage Morgan → 204, статус Triaged. UI: вхід, профіль, вихід (`auth-lab`), «Створити й прочитати» (`browser-lab`), створення й вихід (`session`) працюють. Повний `dotnet test` — PASS.

## Residual risk

Login і register навмисно без antiforgery (login-CSRF / account-creation ризик прийнято, обмежено rate limiter). XSS на тому самому origin може прочитати токен — захист від XSS лишається окремим control (ЛР 5). Production-like cookie-сеанс через реальний HTTPS не перевірявся.
