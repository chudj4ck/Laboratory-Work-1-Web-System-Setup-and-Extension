# Security review SecureLab, ЛР 6

Рівень: **добрий («Добре»)**. Невиконані пункти відмінного рівня позначено «Не входить до обраного рівня».

## 1. Executive summary

Огляд накопиченого fixed state SecureLab (ЛР 2–5, baseline 2-A) виявив і усунув дві проблеми. **F-01 (високий):** змінювальні маршрути, що довіряють authentication cookie, не перевіряли antiforgery token — будь-яка сторінка в тому самому браузері могла створити, змінити чи видалити інцидент, виконати triage або завершити сеанс від імені користувача. Тепер усі п'ять таких маршрутів вимагають request token; без нього — 400 без зміни стану, з токеном — штатна робота. **F-02 (середній):** відповідь 500 втрачала заголовки безпеки; тепер вони встановлюються на всіх класах відповідей. Додатково обмежено частоту пошуку на користувача (3/10 с), додано audit trail для переходу triage і перевірено, що журнали не містять паролів, cookie й токенів. Відомих вразливих NuGet-пакетів не знайдено. Залишкові ризики: login/register без antiforgery (прийнято), відсутність перевіреного HTTPS/HSTS, in-memory limiter для одного instance.

## 2. Scope та exclusions

Межі огляду, активи, суб'єкти, entry points і виключення — `docs/threat-model.md`, розділи 1 і 4.

## 3. System overview і trust boundaries

Схема меж довіри й зв'язок «межа → властивість → перевірка» — `docs/threat-model.md`, розділи 2–3.

## 4. Methodology та test environment

- Review-start commit: `013bf70b94d6706d5da8abeeabf22e74213e24ff` (тег `v0.5.0`), гілка `lab/6-hardening-review`.
- ОС Windows; IDE Visual Studio; .NET SDK 10 (`global.json` 10.0.100, latestFeature, без prerelease); PostgreSQL 18.4 у Docker (`infra/compose.yaml`, 127.0.0.1:54329); браузер Google Chrome.
- Development: `dotnet run --project src/SecureLab.Api` (launch profile `http`, `http://localhost:5080`), reset `-- --reset-database`.
- Production-like: `ASPNETCORE_ENVIRONMENT=Production`, `ASPNETCORE_URLS=http://localhost:5080`, `ConnectionStrings__SecureLab` поза Git, `Logging__Console__IncludeScopes=true`, `dotnet run --project src/SecureLab.Api --no-launch-profile -c Release`.
- Пароль навчальних акаунтів задається лише через `Read-Host` у `SeedUsers__Password`, у Git і докази не потрапляє.

## 5. Findings summary

| ID | Назва | Пріоритет | Статус | Retest |
|---|---|---|---|---|
| F-01 | Cookie-authenticated mutations без antiforgery | високий | Fixed | REG-CSRF-01, `Lab06CsrfTests` |
| F-02 | Відповідь 500 без CSP / nosniff / Referrer-Policy | середній | Fixed | повторна Production 500 + заголовки |

Порядок: спершу F-01 — пряма несанкціонована зміна даних від імені користувача; F-02 — втрата defense-in-depth лише на шляху помилки без витоку даних.

## 6. Detailed findings

Картки — `docs/findings/`.

## 7. Regression results

Передумови: Development, `dotnet run --project src/SecureLab.Api -- --reset-database`, `SeedUsers__Password` у змінній середовища. Автоматичний набір: `dotnet test SecureLab.sln --configuration Release` — **44 тести, failed 0** (перед фінальним прогоном).

| ID у проєкті | Рівень | Property | Негативний сценарій | Позитивна перевірка | Evidence / command | Result |
|---|---|---|---|---|---|---|
| T-02 (`IncidentEndpointTests`, з CSRF-токеном) | добрий | server validation | недопустимий DTO → 400 ValidationProblem з полем errors | допустимий DTO → 201 | `dotnet test`; `GET /api/incidents?status=Unknown` → 400 | pass |
| S-02 (`SearchMechanicsTests`) | достатній | SQLi | спецсимволи в `q` не змінюють структуру SQL (параметр `@pattern`) | звичайний search → 200 | `dotnet test` | pass |
| A01–A07 (`Lab03SecurityTests`) | достатній | authentication | анонімний POST → 401 без redirect; хибний / неіснуючий логін — однакові 401 | login → 204, logout з токеном → 204, `/api/me` → 401 | `dotnet test`; ручний REG-CSRF-01 (logout) | pass |
| A-01…A-12 (`Lab04AuthorizationTests`) | достатній | authorization / IDOR | Alice → чужий інцидент 404; Reporter triage → 403 без зміни | власник 200; Analyst triage 204 | `dotnet test`; ручна перевірка audit | pass |
| REG-XSS-01 (ЛР 5) | достатній | XSS | marker у описі/коментарі не виконується | складний текст відображається буквально | ручна процедура ЛР 5 + `browser-lab.js` (safe helper) | pass |
| REG-CORS-01 (ЛР 5) | добрий | browser origin | 4174 → CORS error, без ACAO | 4173 → 200 + `Access-Control-Allow-Origin: http://localhost:4173` | probes 4173/4174, `curl.exe -H "Origin: …"` | pass |
| REG-CSRF-01 (ЛР 6) | достатній | CSRF | POST/PUT/DELETE/logout/triage без токена → 400, стан незмінний | з токеном: 201 / 204, стан змінено | ручна процедура в Console + `Lab06CsrfTests` | pass |
| REG-RATE-01 (ЛР 6) | добрий | rate limiting search | 4-й запит Alice за 10 с → 429 Problem Details + Retry-After | Bob одночасно → 200; Alice після вікна → 200 | Console двох сеансів + `Lab06RateLimitTests` | pass |
| Login limiter (`Lab03SecurityTests`) | добрий | rate limiting login | 6-та спроба за 60 с → 429, однаково для існуючого й неіснуючого акаунта | після вікна правильний вхід → 204 | Console + `dotnet test` | pass |

## 8. Hardening controls

### 8.1. Периметр змінювальних маршрутів (cookie profile)

Джерела: `git grep -n -E "\.Map(Post|Put|Patch|Delete)\(" -- src` (сервер) і `git grep -n -E "method: *.(POST|PUT|PATCH|DELETE)" -- src/SecureLab.Api/Client` (клієнт), OpenAPI Development, код endpoint-ів. Контракт antiforgery: заголовок `X-CSRF-TOKEN`, cookie `SecureLab.Antiforgery`, видача `GET /api/auth/csrf-token` (після входу), валідація — `AntiforgeryFilter` (`ValidateRequestAsync` → 400 Problem Details).

| ID | Method + route | Джерело / розбіжність | Зміна стану | Cookie authentication | Browser-accessible | Antiforgery validation | Regression ID |
|---|---|---|---|---|---|---|---|
| SC-01 | `POST /api/incidents` | ЛР 2–3; client: browser-lab.js, session.js | створює інцидент | так | так | explicit — `AntiforgeryFilter` | REG-CSRF-01 (POST), T-01/A04 з токеном |
| SC-02 | `PUT /api/incidents/{id}` | ЛР 4; лише API / OpenAPI, UI-кнопки немає | змінює title/description | так | так (HTTP endpoint доступний браузеру) | explicit — `AntiforgeryFilter` | REG-CSRF-01 (PUT), A-04/A-08a |
| SC-03 | `DELETE /api/incidents/{id}` | ЛР 4; лише API / OpenAPI | видаляє інцидент | так | так | explicit — `AntiforgeryFilter` | REG-CSRF-01 (DELETE), A-04 |
| SC-04 | `POST /api/incidents/{id}/triage` | ЛР 4; лише API / OpenAPI | `New → Triaged` (Analyst) | так | так | explicit — `AntiforgeryFilter` | REG-CSRF-01 (triage), A-06/A-07 |
| SC-05 | `POST /api/auth/logout` | ЛР 3; client: auth-lab.js, session.js | завершує сеанс | так | так | explicit — `AntiforgeryFilter` до `SignOutAsync` | REG-CSRF-01 (logout), A06 |
| SC-06 | `POST /api/auth/login` | ЛР 3; client: auth-lab.js, session.js | створює сеанс | ні (не довіряє наявній cookie) | так | absent — обґрунтовано: login-CSRF ризик прийнято в межах огляду; захищений rate limiter 5/60 с; токен до входу потребував би окремого анонімного bootstrap | login limiter (Lab03 A-07/rate-limit тест) |
| SC-07 | `POST /api/auth/register` | ЛР 3; client: session.js | створює обліковий запис | ні | так | absent — обґрунтовано: account-creation CSRF ризик прийнято, не діє від імені наявного користувача | Lab03 реєстрація |

Розбіжностей між сервером, клієнтом і OpenAPI не виявлено: PUT, DELETE і triage не мають UI-кнопок, але як HTTP endpoints доступні браузеру, тому захищені однаково. GET/HEAD/OPTIONS маршрутів, що змінюють стан, немає.

### 8.2. Заголовки безпеки на класах відповідей (Development, Chrome / curl)

| Клас | Method + route | Status | Фактичні значення | Ризик | Межа |
|---|---|---|---|---|---|
| Статична сторінка | `GET /` (anonymous, curl) | 200 `text/html` | CSP `default-src 'self'; … frame-ancestors 'none'`, `nosniff`, `no-referrer` | XSS-наслідки, MIME sniffing, витік referrer, clickjacking | не замінює safe DOM і правильний Content-Type |
| Успішний API | `GET /api/incidents/{id}` (Alice) | 200 JSON | ті самі три заголовки | те саме | не замінює авторизацію |
| Validation | `GET /api/incidents?status=Unknown` (Alice) | 400 ValidationProblem | ті самі | те саме | — |
| Unknown resource | `GET /api/incidents/99999999-…` (Alice) | 404 Problem Details | ті самі | те саме | — |
| Unexpected error | `POST /api/auth/login` (Production, недосяжна БД) | 500 Problem Details | **до fix — відсутні** (F-02); після fix — ті самі три | втрата defense-in-depth на шляху помилки | — |
| Rate limit | `GET /api/incidents/search` (Alice, 4-й запит) | 429 Problem Details | ті самі + `Retry-After` | — | — |

Cookie: `.AspNetCore.Identity.Application` — HttpOnly, SameSite=Lax, Path=/, Secure — SameAsRequest у Development, Always поза Development; `SecureLab.Antiforgery` — HttpOnly, SameSite=Strict. Значення cookie в доказах не наводяться.

### 8.3. CORS (REG-CORS-01, Development)

Policy `Lab05BrowserProbe` реєструється лише в Development: exact origin `http://localhost:4173`, GET, header `X-Lab-Cors-Probe`, credentials. З 4173 `fetch("http://localhost:5080/health")` → 200 і `Access-Control-Allow-Origin: http://localhost:4173`; з 4174 → блок браузером; `curl.exe -H "Origin: http://localhost:4174"` → 200 без ACAO (direct client не застосовує SOP). CORS не замінює authentication, authorization чи antiforgery; два порти localhost не є доказом SameSite.

### 8.4. Rate limiting

| Політика | Endpoint | Partition | Quota / window | 429 | Відновлення | Перевірені partitions |
|---|---|---|---|---|---|---|
| `search-limit` (ЛР 6) | `GET /api/incidents/search` | `user:{NameIdentifier}` з principal (не IP, не заголовок клієнта) | 3 / 10 с, без черги | Problem Details «Забагато запитів», `Retry-After` | через ≈11 с → 200 | Alice (200 200 200 429) і Bob (одночасно 200) |
| `login-limit` (ЛР 3) | `POST /api/auth/login` | IP клієнта | 5 / 60 с | 429 однаково для існуючого й неіснуючого акаунта | через ≈61 с → 204 | анонімний клієнт |

Обмеження частоти не замінює авторизацію: Alice з вичерпаною квотою отримує 404 на чужий інцидент, а не дані. In-memory limiter — лише для одного instance API.

### 8.5. HTTPS / HSTS

`Properties/launchSettings.json` містить лише профіль `http` (`http://localhost:5080`); `UseHttpsRedirection()` і `UseHsts()` у `Program.cs` відсутні. Локальний HTTP-профіль не доводить безпеки транспорту в production; реальний TLS, redirect і HSTS не тестувалися (виключення, розділ 2).

### 8.6. Development vs Production

| Властивість | Development | Production-like |
|---|---|---|
| `Hosting environment` | Development | Production |
| OpenAPI `/openapi/v1.json` | 200 | 404 Problem Details |
| `/scalar/v1` | UI Scalar | SPA fallback клієнта (200 text/html) |
| Reset даних | дозволено | `InvalidOperationException` — відмова |
| Connection string | `appsettings.Development.json` (study-only) | лише `ConnectionStrings__SecureLab` поза Git |
| CORS probe policy | зареєстровано | відсутня |
| Auth cookie Secure | SameAsRequest | Always |
| Unexpected error | 500 Problem Details + traceId | те саме, без stack trace |

## 9. Dependency and secret audit

### 9.1. Tracked configuration

`git ls-files '*appsettings*.json' '*.env*' '*compose*.yml' '*compose*.yaml' '*.config'` → `infra/compose.yaml`, `src/SecureLab.Api/appsettings.json`, `src/SecureLab.Api/appsettings.Development.json`. Файлів `.env` у Git немає.

### 9.2. Пошук потенційних секретів у tracked files

Команда: `git grep -n -I -i -E 'password|passwd|secret|api.?key' -- .` — **84 збігів** (на review-start state). Межі: лише поточні tracked files; історія, stash, інші клони й CI не скануються.

| Шлях:рядок | Контекст | Рішення | Причина й межа |
|---|---|---|---|
| `infra/compose.yaml:9` | `POSTGRES_PASSWORD` локального контейнера, порт 127.0.0.1 | accepted, study-only | README:63 позначає значення як відкрите навчальне; не поширюється на інші БД і середовища |
| `src/SecureLab.Api/appsettings.Development.json:3` | connection string Development | accepted, study-only | те саме навчальне значення; поза Development не читається; для реального — `ConnectionStrings__SecureLab` |
| `src/SecureLab.Api/Data/SecureLabDesignTimeDbContextFactory.cs:10` | design-time connection string для EF CLI | accepted, study-only | узгоджене навчальне значення; видалення зламало б стенд |
| `README.md:63, 138` | документація про навчальні значення й заборону секретів | не секрет | текст |
| `docs/git-workflow.md:124`, `docs/report-lab-04.md:94` | документація | не секрет | текст |
| `.gitignore:14` | коментар розділу ігнорування | не секрет | текст |
| `src/SecureLab.Api/Client/*.html, *.js` | поля форм `password`, очищення поля | не секрет | назви полів, значення немає |
| `src/SecureLab.Api/Data/DbSeeder.cs:40–56, 184–210` | читання ключа `SeedUsers:Password` | не секрет | значення задається поза Git (змінна середовища) |
| `src/SecureLab.Api/Scaffolding/Lab03Identity.cs` | DTO `Password`, `RequiredLength`, `PasswordSignInAsync` | не секрет | назви полів і параметрів |
| `Data/Migrations/*` | колонка `PasswordHash` | не секрет | схема БД |
| `tests/SecureLab.Api.Tests/*.cs` | `Environment.GetEnvironmentVariable("SeedUsers__Password")`, випадкові `Wrong-<guid>` | не секрет | значення поза Git; згенеровані хибні паролі |
| `tests/http/lab-04-access.http:9, 23, 33` | `{{$processEnv SeedUsers__Password}}` | не секрет | значення з процесної змінної |
| `tests/SecureLab.Api.Tests/packages.lock.json:208, 291` | пакет `Microsoft.Extensions.Configuration.UserSecrets` | не секрет | ідентифікатор залежності |

Висновок: реальних credentials у поточних tracked files не знайдено. Порожній або «безпечний» результат шаблону не доводить відсутності секретів, записаних іншими словами. Якби реальне значення потрапило в Git, самого видалення з поточного файла недостатньо: воно лишається в історії, клонах і кешах, тому потрібні відкликання/rotation.

### 9.3. Dependency audit

- SDK: `dotnet --version` → **10.0.403** (обрано `global.json` 10.0.100 / latestFeature / без prerelease).
- Дата: 18.11.2026. Команди: `dotnet restore` (Restore complete, Build succeeded, NU1901–NU1904 не виведено), `dotnet package list --vulnerable --include-transitive` (код завершення **0**), `dotnet package list --vulnerable --include-transitive --format json`.
- Джерела: `https://api.nuget.org/v3/index.json`, `C:\Program Files (x86)\Microsoft SDKs\NuGetPackages\`.
- Результат: «The given project `SecureLab.Api` has no vulnerable packages given the current sources.» і те саме для `SecureLab.Api.Tests`; у JSON для обох проєктів відсутній масив `vulnerablePackages`.

| Package | Version | Direct / transitive | Advisory / severity | Використання функціональності | Доступне оновлення | Рішення і причина |
|---|---|---|---|---|---|---|
| Microsoft.AspNetCore.OpenApi | 10.0.10 | direct (Api) | не повідомлено | `MapOpenApi()` лише в Development | не перевірялось як потреба | keep — advisory немає; OpenAPI недоступний у Production (404) |
| Microsoft.OpenApi | 2.7.5 | direct (Api) | не повідомлено | генерація документа OpenAPI | — | keep |
| Microsoft.AspNetCore.Identity.EntityFrameworkCore | 10.0.10 | direct (Api) | не повідомлено | Identity, cookie authentication | — | keep — security-critical пакет, стежити за оновленнями 10.0.x |
| Microsoft.EntityFrameworkCore (+ .Relational, .Design) | 10.0.10 | direct (Api) | не повідомлено | доступ до БД; Design — лише для інструментів EF | — | keep |
| Npgsql.EntityFrameworkCore.PostgreSQL | 10.0.3 | direct (Api) | не повідомлено | провайдер PostgreSQL, параметризовані запити | — | keep |
| Scalar.AspNetCore | 2.16.16 | direct (Api) | не повідомлено | UI `/scalar` лише в Development (у Production — fallback клієнта) | — | keep; сторонній UI — залишковий ризик лише Development |
| Microsoft.AspNetCore.Mvc.Testing, Microsoft.NET.Test.Sdk, xunit 2.9.3, xunit.runner.visualstudio, coverlet.collector | 10.0.10 / 17.14.1 / 2.9.3 / 3.1.4 / 6.0.4 | direct (Tests) | не повідомлено | лише тестовий проєкт, не публікується | — | keep |
| Транзитивні залежності обох проєктів (`packages.lock.json`) | за lockfile | transitive | не повідомлено | — | — | keep; RestorePackagesWithLockFile фіксує версії |

Придушень (`NuGetAuditSuppress`, `WarningsNotAsErrors` для NU190x) немає; `packages.lock.json` у ЛР 6 не змінювався.

**Межа висновку:** перевірено лише **відомі на цю дату** advisories вказаних джерел для версій із lockfile. Відсутність виводу не доводить безпечності графа залежностей: невідомі вразливості, досяжність коду й supply-chain ризики (компрометація пакета) не оцінювалися. Код завершення 0 сам по собі не є доказом.

### 9.4. Журнали та audit trail

Журнал консолі API збережено поза Git (`..\lr06-logs\api.log`, `Tee-Object`), сценарії: успішний вхід, невдалий вхід, validation 400, відмова Reporter (triage → 403, статус New), дозволений перехід Morgan (triage → 204, Triaged), unexpected error (Production, недосяжна БД, 500 з traceId — той самий TraceId у `ExceptionHandlerMiddleware`).

Події: `authorization.denied` (`SecureLab.Authorization`: subject, action `incident.triage`, resource, result denied, час, trace) і `audit.event` (`SecureLab.Audit`: subject, action, resource, result success, `New -> Triaged`, час, trace — записується лише після `SaveChangesAsync`). Перевірка `Select-String` по файлу журналу:

| Шаблон | Збігів |
|---|---|
| значення `SeedUsers__Password` (зі змінної середовища) | 0 |
| `NotARealPassword1!` | 0 |
| `Wrong-password` (хибні паролі сценарію login limiter) | 0 |
| `cookie:` / `set-cookie` | 0 |
| `X-CSRF-TOKEN` | 0 |
| `audit.event` | 1 |
| `authorization.denied` | 1 |

Межа висновку: лише ці сценарії й цей sink (console log). Повідомлення будуються structured logging без конкатенації user input.

## 10. Residual risks

- Login і register без antiforgery (login-CSRF, account creation) — прийнято; пом'якшено login limiter.
- Реальний HTTPS, HSTS і production deployment не перевірялися; Production-like cookie-сеанс через HTTPS не тестувався.
- Rate limiter in-memory: стан не спільний між кількома instances; login limiter за IP може зачепити користувачів за спільним NAT.
- XSS на тому самому origin нівелює CSRF-токен; захист — safe DOM і CSP (ЛР 5).
- Dependency audit охоплює лише відомі на дату перевірки advisories.
- Секрети перевірено лише в поточних tracked files; історія, інші клони й CI — поза межами.

## 11. Conclusion

Межі огляду, модель загроз і зв'язок меж довіри з тестами зафіксовано; реальних секретів у tracked files немає; production-like профіль змістовно відрізняється від Development і не розкриває внутрішніх деталей у 500. Усі cookie-authenticated змінювальні маршрути захищено antiforgery (F-01), заголовки безпеки охоплюють шлях помилки (F-02), пошук обмежено per-user, привілейований перехід має audit trail, журнали не містять credentials. Повний regression pack доброго рівня пройдено.

## 12. Evidence appendix

Очищені докази — рисунки звіту ЛР 6 (Word/PDF) у порядку етапів 1–4: git-стан і review-start; threat model; secret search і класифікація; Production profile, OpenAPI 404, reset-відмова, 500 + traceId і заголовки (F-02 до/після); headers на класах відповідей і cookie; REG-CORS-01; периметр; F-01 до; REG-CSRF-01 (POST, PUT, DELETE, logout, triage); UI-прохід; REG-RATE-01 і login limiter; dependency audit; audit/log review; `dotnet test`; merge, регресія merged-стану й тег `v1.0.0`. Значення паролів, cookie й токенів у доказах відсутні або приховані.

## Декларація використання ШІ

Використано Claude як асистента для плану, коду й документації; кожну зміну перевірено запуском, тестами й ручними сценаріями. Паролі, cookie й токени не передавались.
