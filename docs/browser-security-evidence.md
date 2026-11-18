# Докази безпеки браузера (DEL-01)

Рівень: **добрий («Добре»)**. Рівні накопичувальні; повні критерії й маршрут — на початку практичної частини методички. Заповнюйте лише розділи свого рівня й усі попередні. Не записуйте паролі, cookie/token values чи export browser storage.

## Стенд і Git-стан (Для всіх)

ОС: Windows 11; browser: Mozilla Firefox (укр. інтерфейс), для CORS/CSP — також Chromium-браузер; API і клієнт: http://localhost:5080; probes: http://localhost:4173 (allowed), http://localhost:4174 (disallowed). IDE: Visual Studio; SDK .NET 10.

Receipt `.scaffolds/lab-05.json`: release `lab-05-start-v1`, inherits `v0.4.0`, base_commit `fac76df42c5639c89275c23178bfed3f1239a18e`, entry_parent `fac76df42c5639c89275c23178bfed3f1239a18e` (commit політики SDK не потрібен — global.json уже містив 10.0.100 / latestFeature).

Гілка `lab/5-browser-xss` від `v0.4.0`. Hashes:
- vulnerable commit (scaffold installed): `511b59272f1b773f625abb10f15b9f37fad6e477`;
- seed-commit другого sink (публічний коментар `…000000000005` з marker): `5b577c7ccaf93b087be73152f856e8b570819147`;
- XSS fix (safe DOM helper для Description і comments): `561d456ce655d4311d092ac039e8aae71d185e22`;
- **fixed commit = тег `v0.5.0`** (CORS Development policy, enforcement CSP, докази): `013bf70b94d6706d5da8abeeabf22e74213e24ff`;
- `main` переведено fast-forward на fixed commit; хеші записано наступним окремим commit «Record lab 5 hashes».

Спосіб передавання: приватний remote https://github.com/chudj4ck/Laboratory-Work-1-Web-System-Setup-and-Extension (гілка `lab/5-browser-xss`, тег `v0.5.0`, `main`).

Механізм сеансу: cookie `.AspNetCore.Identity.Application` (ASP.NET Core Identity), host-only `localhost`, Path `/`, HttpOnly = true, SameSite = Lax, Secure — SameAsRequest у Development (http-стенд), Always поза Development. Value не записується.

## Гіпотеза й REG-XSS-01 (Для всіх)

**Карта Description:** source — поле «Опис нового інциденту» на `/browser-lab.html` (вводить автор) → transformations — `JSON.stringify` у `POST /api/incidents`, серверна валідація довжини (≤ 4000) без зміни тексту → storage — `incidents.description` (PostgreSQL) → response — `GET /api/incidents/{id}`, поле `description` → sink — `browser-lab.js`, `#description.innerHTML` (HTML-контекст).

**Карта IncidentComment.Text (Добре):** source — seed (у продукті — будь-який автор коментаря) → storage — `incident_comments.text` → response — `comments[].text` → sink — `paragraph.innerHTML` у циклі відображення коментарів.

**Гіпотеза:** значення з API потрапляє в HTML-парсер через `innerHTML`, тому збережений текст із тегом і inline handler виконується в сеансі будь-якого глядача.

**Передумови REG-XSS-01:** гілка `lab/5-browser-xss`; reset `dotnet run --project src/SecureLab.Api -- --reset-database`, запуск `dotnet run --project src/SecureLab.Api`; акаунти alice (автор) і morgan (Analyst, глядач); marker — один рядок з `resources/lab05-marker.txt`; запис створюється формою «Створити й прочитати», читається кнопкою «Прочитати» за Guid; seed-коментар — інцидент `20000000-0000-0000-0000-000000000001`, коментар `30000000-0000-0000-0000-000000000005`.

| Спостереження | До fix (`511b592` / `5b577c7`) | Після fix (`561d456`) | Посилання на доказ |
|---|---|---|---|
| Значення в БД/API | `description` і `comments[].text` містять marker повністю | те саме значення без змін | звіт, рис. 15, 25 / 30, 32–33 |
| DOM основного Description | у `#description` створено `<img src="x" onerror=…>` | `<p>` з текстовим вузлом, `img` = null | рис. 17 / 34–36 |
| DOM коментаря | `<img>` у другому `<p>` `#comments` | текстовий вузол, `img` = null | рис. 24 / 28–29 |
| Дія marker | `data-lab05-marker` = `executed` | `null` | рис. 16, 23 / 27, 37 |
| Апостроф/лапки, 5 < 7, Unicode, HTML-like рядок | `<b>жирний</b>` інтерпретовано як жирний текст | усі рядки відображено буквально, `<b>` видно як текст | рис. 9 / 41–44 |
| Довжина за власними правилами ЛР 2 | 3900 символів (межа 4000) — `GET: 200` | без змін | рис. 11 |
| Вікно Morgan: GET і перевірка marker; контроль Bob | Morgan: `GET: 200`, `executed` (stored XSS); Bob — 404 за матрицею ЛР 4, не є доказом XSS | Morgan: marker текстом, перевірки `null` | рис. 18–20 / 38–40 |

**Finding.** Актив — сеанс браузера користувача та дані, доступні від його імені. Передумови — локальний акаунт із правом створювати інцидент (контроль над текстовим полем). Першопричина — недовірене значення з API передавалося в HTML-sink `innerHTML` (опис і коментарі) у `browser-lab.js`. Вплив на стенді — лише локальна дія marker (атрибут на прихованому елементі) у сеансах Alice і Morgan. Виправлення — єдиний safe helper `createTextElement` (`createElement` + `textContent`) і `replaceChildren` для обох полів; дані не фільтруються й не змінюються. Retest — той самий marker відображається як текст, дія не відбувається, збережене значення не змінилося. Залишковий ризик — інші/майбутні sinks поза досліджуваним flow, сторонній код (Development-довідник `/scalar`), контексти URL/атрибутів не досліджувались на рівні «Добре».

**REG-XSS-01 (повторювана процедура).** 1) reset і запуск; 2) вхід alice на `/auth-lab.html`; 3) на `/browser-lab.html` команда `document.querySelector("#lab05-marker-target").getAttribute("data-lab05-marker")` → `null`; 4) створити інцидент з marker, прочитати; 5) прочитати `…0001` (seed-коментар); 6) Очікування на fixed: marker видно текстом, `#description`/`#comments` не містять `img`, перевірка → `null`, JSON містить marker без змін. Негативний контроль: на `511b592` (опис) і `5b577c7` (коментар) перевірка повертає `executed`.

## CORS і REG-CORS-01 (Для всіх)

Прогноз (зафіксовано до зміни policy):

| Сценарій | Чи доходить request до API? | Чи може JavaScript прочитати response? | Чому |
|---|---|---|---|
| same-origin 5080 → API | так | так | той самий origin, CORS не потрібен |
| simple GET 4173 → API | так | ні (до policy) | немає `Access-Control-Allow-Origin` |
| simple GET 4174 → API | так | ні | немає `Access-Control-Allow-Origin` |
| curl/.http → API | так | не застосовується | direct client не застосовує SOP |
| preflighted 4173 → API («Добре») | лише OPTIONS; actual GET не надсилається | ні | preflight без дозволів (405) |

Команди probes (з кореня проєкту, окремі вікна PowerShell):
`py -3 -m http.server 4173 --bind localhost --directory demonstrations/cors-probe` і те саме з `4174`.
Policy `Lab05BrowserProbe` — **навчальний Development-стенд**: реєструється й застосовується лише в Development; exact origin `http://localhost:4173`, метод `GET`, заголовок `X-Lab-Cors-Probe`, `AllowCredentials()`. `http://localhost:4174` — негативний контроль. Штатна топологія — same-origin `http://localhost:5080`, вона від policy не залежить. У Production policy відсутня.

| Клієнт / простий запит | До policy | Fixed state | Status, ACAO, Console / доказ |
|---|---|---|---|
| Same-origin 5080 | 200 | 200 | без CORS (рис. 5) |
| Allowed 4173 | CORS error (немає ACAO) | `{status: 200, body: {"status":"ready"}}` | ACAO `http://localhost:4173` (рис. 49 / 56, 58) |
| Disallowed 4174 | CORS error | CORS error | ACAO відсутній (рис. 50 / 57) |
| Direct HTTP / curl | 200 | 200 | curl читає відповідь; для 4174 ACAO відсутній (рис. 68–69) |

**Перевірка порядку middleware:** `UseRouting` → `UseCors` → `UseAuthentication` → `UseAuthorization` → `UseRateLimiter`. Із 4173 без cross-origin cookie `fetch("/api/incidents")` повернув число `401` (рис. 55): JavaScript читає HTTP-відмову, CORS працює до авторизації.

**Різниця browser / direct HTTP:** same-origin policy — правило браузера для web content; curl його не застосовує й читає будь-яку відповідь, але проходить ті самі серверні controls: `GET /api/incidents` без cookie → 401 (рис. 70). CORS не захищає API від прямих клієнтів і не замінює authentication/authorization.

**REG-CORS-01 (fixed state):**
`curl.exe -sS -D - -o NUL -H "Origin: http://localhost:4173" http://localhost:5080/health` → 200, `Access-Control-Allow-Origin: http://localhost:4173`, `Access-Control-Allow-Credentials: true`, CSP, nosniff, no-referrer (рис. 86).
`curl.exe -sS -D - -o NUL -H "Origin: http://localhost:4174" http://localhost:5080/health` → 200, CSP, nosniff, no-referrer, **без** `Access-Control-Allow-*` (рис. 87). Статус 200 для 4174 — не помилка: сервер запит виконав, читати відповідь заборонив би браузер.

## Додатково для Добре та Відмінно

**Другий flow IncidentComment.Text:** публічний seed-коментар `30000000-0000-0000-0000-000000000005` (автор Morgan, `IsInternal = false`) до інциденту Alice `…0001`, текст — канонічний marker (`DbSeeder.cs`, константа `Lab05Marker`, commit `5b577c7`). До fix — `<img>` у `#comments` і `executed` (рис. 23–25); після fix — текстовий вузол, `null`, текст у JSON без змін (рис. 27–30). Тести ЛР 4 не перевіряють кількість коментарів — похідних змін не потрібно.

**Єдиний safe helper:** `createTextElement(tagName, text, className)` у `src/SecureLab.Api/Client/browser-lab.js`; викликається для `#description` і кожного `comments[].text` через `replaceChildren` (commit `561d456`, рис. 26). `innerHTML` у файлі відсутній.

**Preflight:** до policy з 4173 і 4174 — OPTIONS 405, actual GET не виконано, Console: «Response to preflight request doesn't pass access control check» (рис. 51–52). Після policy з 4173 — preflight дозволено, GET 200 (рис. 56); з 4174 — OPTIONS 204 **без** `Access-Control-Allow-*`, GET заблоковано (рис. 57, 59). Статус OPTIONS не є ознакою дозволу — вирішують заголовки.

**Cookie-дослід:** після входу alice кнопка GET на 4173 (`credentials: "include"`) → 200 і список; request містить `Origin: http://localhost:4173`, response — exact ACAO і `Allow-Credentials: true` (рис. 61–62). 4174 → «Браузер не надав response JavaScript» (запит до API дійшов разом із cookie, але відповідь не надано сторінці; рис. 63). Без `AllowCredentials()` 4173 → відмова «…Access-Control-Allow-Credentials… must be 'true'» (рис. 64–65). Після повернення в анонімному вікні без входу → 401 з ACAO і `Allow-Credentials: true` (рис. 66–67). Кінцевий `AllowCredentials()` — лише в Development policy для одного origin 4173; `AllowAnyOrigin()` не використано. Cookie надсилається з 4173 на 5080, бо порт не входить до поняття site (SameSite=Lax), хоча origins різні.

**Review XSS / CORS / CSRF / authorization:** див. DEL-03 (звіт). Коротко: XSS — браузер виконує недовірені дані як код (виправлено safe DOM); CORS — чи надає браузер cross-origin response JavaScript (не захищає API); CSRF — браузер сам надсилає cookie зі state-changing запитами з іншого site, потрібен окремий antiforgery control (ЛР 6); authorization — серверне рішення ЛР 4, діє для будь-якого клієнта.

| Директива CSP | Фактичні ресурси застосунку | Обране джерело / причина |
|---|---|---|
| default-src | документи `/`, `/browser-lab.html`, `/auth-lab.html` з 5080 | `'self'` — fallback для неназваних типів |
| script-src | `app.js`, `browser-lab.js`, `auth-lab.js`, `session.js` — лише з 5080 (рис. 71–73) | `'self'`; inline scripts немає, `unsafe-inline` не потрібен |
| style-src | `styles.css`, `session.css` з 5080; inline `<style>` сторінки `session.html` перенесено в `session.css` | `'self'` без `unsafe-inline` |
| connect-src | fetch до `/api/...` того самого origin | `'self'`; навчальні 4173/4174 не додано |
| img-src | власних зображень немає | `'self'`; кероване порушення `new Image()` до 4173 заблоковано (рис. 81) |
| frame-ancestors | вбудовування не потрібне | `'none'` (немає fallback до default-src, вказано явно) |

Додатково: `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`.

**Місце зміни:** наявна спільна middleware заголовків у `Program.cs` (після `UseStatusCodePages`, до статичних файлів); один header `Content-Security-Policy` (enforcement). Виняток — лише `/scalar` у Development (сторонній UI-package; залишковий ризик). Enforcement: документ 200 з одним CSP header (рис. 80, 85); `/`, `/browser-lab.html`, `/auth-lab.html` працюють без порушень (рис. 82–84); `new Image().src = "http://localhost:4173/x.png"` → «violates … img-src 'self' … blocked» (рис. 81). Report-only для «Добре» не виконувався.

| Header / control | Фактичне значення | Ризик і межа захисту / policy rationale |
|---|---|---|
| X-Content-Type-Options | `nosniff` (baseline) | забороняє MIME sniffing; не замінює правильний Content-Type (`text/javascript` для JS, рис. 76) |
| Referrer-Policy | `no-referrer` (baseline) | не передає адресу сторінки (Guid інцидентів у URL) стороннім сайтам; клієнт не потребує referrer для навігації, тому залишено; не дозволяє класти секрети в URL |
| frame-ancestors | `'none'` у CSP | захист від clickjacking/вбудовування; не замінює authorization чи XSS fix |

**CSP — defense in depth:** за enforcement `script-src 'self'` inline handler marker не виконається навіть на vulnerable commit, тому висновок про виправлення sink зроблено за DOM (текстовий вузол, `img` = null), а не за відсутністю marker-ефекту.

## Додатково для Відмінно

Не виконувалось — обрано рівень «Добре».
