# F-02. Відповідь 500 не містила заголовків безпеки (CSP, nosniff, Referrer-Policy)

**Статус:** Fixed
**Актив:** браузерний контекст клієнта (захист від MIME sniffing, витоку referrer, вбудовування й небажаних джерел ресурсів).
**Компонент:** `src/SecureLab.Api/Program.cs` — middleware заголовків і `UseExceptionHandler`.
**Пріоритет:** середній. Impact — на шляху помилки зникає defense-in-depth (CSP, nosniff, Referrer-Policy, frame-ancestors); сама відповідь 500 — Problem Details без внутрішніх деталей, тому прямого витоку немає. Likelihood — висока для відтворення: будь-яка необроблена помилка (недоступна БД).

## Відтворення (до виправлення)

1. Production-like запуск (`--no-launch-profile`, `-c Release`) з недосяжною БД (порт 54399).
2. `curl.exe -s -o NUL -D - -X POST http://localhost:5080/api/auth/login -H "Content-Type: application/json" --data-binary "@lab6-login.json"` (вигаданий пароль).
3. Фактично: `500`, `application/problem+json`, лише `Cache-Control`, `Expires`, `Pragma`; **немає** `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`.
4. Контроль: статична сторінка, 200 API, 400 validation і 404 — усі три заголовки присутні.

## Першопричина

Заголовки встановлювалися в middleware, розміщеній після `UseExceptionHandler`, до виклику `next()`. Під час необробленого винятку `ExceptionHandlerMiddleware` очищає відповідь (`Response.Clear()`), видаляючи вже записані заголовки, і пише Problem Details без них.

## Виправлення

Middleware перенесено перед `UseExceptionHandler`, а заголовки встановлюються в `Response.OnStarting` — безпосередньо перед надсиланням будь-якої відповіді, зокрема після очищення обробником помилок. `Referrer-Policy` задається індексатором (без дублювання). Виняток для Development `/scalar` збережено.

## Retest

Той самий Production-like сценарій із недосяжною БД і той самий запит: `500` Problem Details тепер містить `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`; тіло досі без stack trace, є `traceId`.

## Positive regression

Статична сторінка, 200, 400, 404 і 429 мають ті самі заголовки без дублювання; клієнт працює під CSP; повний `dotnet test` — PASS.

## Residual risk

Перевірено один клас 500 (недосяжна БД) у локальному production-like профілі; помилки, що виникають до цієї middleware (на рівні сервера Kestrel), не охоплено. HSTS і HTTPS не перевірялися.
