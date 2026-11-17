# Звіт ЛР04 — Авторизація, ролі, володіння ресурсом та IDOR/BOLA

Виконав: Сінельник Андрій Олександрович, група КБ-42.

## Контекст і межа виконання
- Рівень: **добрий** («Добре»). Реалізовано головну action, усі змінювальні дії Incident, список,
  привілейований перехід `New → Triaged`, child resource `IncidentComment`, internal comment і audit відмови.
  Розділ відмінного рівня — «не виконувалось — рівень відмінний».
- Baseline 2-A; base tag `v0.3.0` → commit `b99f57bd35b8360e0939c0cc49d3a933f1be699b`.
- Головна action — `GET /api/incidents/{id}` (details). Політика: чужий/невидимий ресурс — `404`
  (як неіснуючий), видимий ресурс без права на дію — `403`, анонім — `401`, недопустимий перехід — `409`.
- Маршрути рівня: `GET /api/incidents`, `GET /api/incidents/{id}`, `PUT /api/incidents/{id}`,
  `DELETE /api/incidents/{id}`, `POST /api/incidents/{id}/triage`, `GET /api/incident-comments/{id}`.
- ЛР3 після тегу не виправлялась; тег `v0.3.0` не пересунуто.

## Матриця і server-side рішення
Матриця, політика 403/404 і очікувані відповіді — `docs/access-matrix.md`.

- Ідентифікатор і роль беруться лише з principal: `IncidentAccess.TryGetViewer`
  (`ClaimTypes.NameIdentifier`, `IsInRole(Analyst)`). Поля `role`, `ownerUserId`, `status` з тіла запиту не читаються.
- Query scoping: `IncidentAccess.VisibleTo(viewer)` у `IncidentQueries.GetListAsync` і `GetDetailsAsync`
  (Reporter/Administrator — лише власні, Analyst — усі). Internal comments у details — лише для Analyst.
- Централізоване рішення: `IncidentAccess.Decide(viewer, incident, operation)` → `Allow / NotFound / Forbidden`
  для `Read`, `UpdateContent`, `Delete`, `Triage`. Рішення приймається для завантаженого (tracked) ресурсу до змін.
- Дозволений DTO оновлення: `UpdateIncidentRequest(Title, Description)`; server-managed поля
  (`OwnerUserId`, `Status`, `Severity`, `CreatedAtUtc`, `UpdatedAtUtc`) клієнт не задає.
- Triage: наступний статус визначає сервер; дозволено лише з `New`; запис у `IncidentStatusHistory`.
- Child resource: `GET /api/incident-comments/{id}` — умова на parent incident і `IsInternal` в одному запиті.
- Administrator не має опублікованих прав на Incident і діє як звичайний автентифікований користувач.

## Вразливий стан і PoC
- Vulnerable commit: `ef86f60d1ab1361d83bfd1a6c7ace5d60d27d33a`.
- Alice → власний інцидент `20000000-…-0001`: `200 OK` (очікувано allow).
- Alice → інцидент Bob `20000000-…-0002`: `200 OK` з даними Bob (очікувано 404) — **IDOR/BOLA**.
- Список для Alice містив інциденти Bob; анонімний запит до details також повертав дані.
- Докази — скріни відповіді (status і title), без cookie, пароля та заголовків `Set-Cookie`.

## Виправлення та retest
- Fixed commit: `fac76df42c5639c89275c23178bfed3f1239a18e` (тег `v0.4.0`).
- Ті самі запити після виправлення: Alice → Bob `404 "Інцидент не знайдено"`; Alice → своє `200`;
  Morgan → Alice `200`; анонім → `401`.
- Mutation: стан до/після перевіряється повторним читанням з БД у тестах A-04, A-06, A-07, A-08a.
- Read: DTO не містить `ownerUserId`/email; Reporter не отримує internal comment.
- 404 для чужого й неіснуючого id однакові (status, `Content-Type`, тіло без `traceId`) — тест A-10.

## Доказова таблиця

| ID | Рівень | Сценарій | Передумови | Дія | Очікувано | Фактично | Доказ |
|---|---|---|---|---|---|---|---|
| A-01 | добрий | Анонімний доступ | без cookie | details/PUT/DELETE/triage | `401`, без redirect | `401`, `Location` відсутній | `A01_AnonymousRequests_Return401WithoutRedirect`; curl |
| A-02 | достатній | Власний ресурс | Alice, `…0001` | `GET /api/incidents/{id}` | allow | `200 OK` | `A02_AliceReadsOwnIncident_Returns200` |
| A-03 | достатній | Чужий ресурс | Alice, `…0002` (Bob) | той самий GET з чужим id | `404` | `404 "Інцидент не знайдено"` | `A03_AliceReadsBobIncident_Returns404` |
| A-03R | достатній | Аналітичний read | Morgan, `…0001` | GET; потім PUT | GET allow; PUT deny | `200`; PUT `403`, стан без змін | `A03R_AnalystReadsAliceIncident_Returns200ButCannotUpdate` |
| A-04 | добрий | Чужий ресурс, mutation | Alice, `…0002` | PUT/DELETE | deny, стан без змін | `404`/`404`, title/description/UpdatedAt не змінились, запис існує | `A04_AliceUpdatesOrDeletesBobIncident_Returns404AndStateUnchanged` |
| A-05 | добрий | List | Alice; Morgan | `GET /api/incidents` | лише дозволена множина | Alice — лише власні; Morgan — усі | `A05_ListIsScopedToOwnerForReporter_AndFullForAnalyst` |
| A-06 | добрий | Вертикальне підвищення | Alice (Reporter), власний New | `POST …/triage` | deny, status без змін | `403`, статус New, історія без змін | `A06_ReporterTriagesOwnIncident_Returns403AndStatusUnchanged` |
| A-07 | добрий | Дозволена привілейована дія | Morgan (Analyst), інцидент New | `POST …/triage`, повтор | allow; повтор — 409 | `204`, Triaged, 1 запис історії; повтор `409` | `A07_AnalystTriagesNewIncident_Returns204ThenRepeatReturns409` |
| A-08a | добрий | Overposting ігнорується | Alice, власний інцидент | PUT з `status`, `ownerUserId`, `role` | змінюється лише content | `204`; змінено title/description; status, owner, severity — без змін | `A08a_OwnerUpdateWithForgedFields_ChangesOnlyTitleAndDescription` |
| A-08b | добрий, альтернатива | Відхилення зайвого поля | — | — | — | не виконувалось — обрано A-08a | — |
| A-09 | добрий | Audit event | Alice → triage | рядок у виводі API | `authorization.denied` без секретів | subject, action `incident.triage`, resource, `denied`, UTC, trace = `traceId` відповіді | скрін журналу API + відповідь 403 |
| A-10 | добрий | Нерозрізнюваність 404 | Alice; id Bob і випадковий id | два GET | однакові status, `Content-Type`, тіло без `traceId` | збігаються | `A10_ForeignAndUnknownIncident_ReturnIndistinguishable404` + дві відповіді |
| A-11 | відмінний | search, severity-summary | — | — | — | не виконувалось — рівень відмінний | — |
| A-12 | добрий | Child та internal comment | Alice; Morgan; comment-2 і internal `…0003` | `GET /api/incident-comments/{id}`, details | Reporter — deny, internal не в details; Analyst — allow | Alice `404`/`404`, internal відсутній; Morgan `200`, internal у details | `A12_ChildCommentAndInternalComment_FollowParentAuthorization` |

Додатково: `A03b_AdministratorWithoutPublishedRights_Returns404ForForeignIncident` — Administrator не має обходу ownership.

## Основний finding і залишковий ризик
- **Контекст:** details інциденту за id для автентифікованого користувача.
- **Гіпотеза:** сервер не перевіряє власника ресурсу.
- **Стан до:** commit `ef86f60`; Alice отримує інцидент Bob (`200`).
- **Першопричина:** запит до БД фільтрував лише за `Id`, без умови видимості; рішення про доступ відсутнє.
- **Fix:** правило видимості в запиті (`VisibleTo`), централізоване `Decide`, вузький DTO оновлення, роль із principal.
- **Retest:** Alice → Bob `404`, тіло як для неіснуючого id.
- **Позитивна регресія:** Alice → своє `200`, Morgan → будь-який `200`, triage Analyst `204`.
- **Залишковий ризик:** search і severity-summary не обмежені множиною (рівень відмінний); CSRF для cookie-mutation —
  задокументований навчальний борг до ЛР 6.

## Browser flow
Вхід як Alice на головній сторінці → власні details (`200`) → probe інциденту Bob у консолі DevTools (`404`).
Після входу як Morgan — читання обох інцидентів (`200`). Значень credentials, cookie чи `Set-Cookie` у знімках немає.

## Добрий рівень: роль, transition, child, audit
- Alice (Reporter) → triage власного New: `403`, статус New. Morgan (Analyst) → triage New: `204`, сервер встановив Triaged;
  повтор `409 "Перехід неможливий"`.
- Morgan читає коментар до інциденту Bob і internal comment до інциденту Alice (`200`); Alice — `404` для обох,
  internal відсутній у details.
- Audit: `authorization.denied` з subject id, action, resource id, result, UTC-часом і traceId, що збігається з `traceId` у Problem Details.

## Відмінний рівень
Не виконувалось — рівень відмінний.

## Перевірки, відтворення і подання
- Windows 11, .NET SDK 10, PostgreSQL 18.4 у Docker (`infra/compose.yaml`).
- Пароль seed вводиться через `Read-Host` у змінну середовища `SeedUsers__Password`, у Git не потрапляє.
- Скидання бази: `dotnet run --project src/SecureLab.Api -- --reset-database`.
- Тести: `dotnet build SecureLab.sln`; `dotnet test SecureLab.sln --filter "FullyQualifiedName~Lab04AuthorizationTests"`;
  `dotnet test SecureLab.sln`.
- Vulnerable commit: `ef86f60d1ab1361d83bfd1a6c7ace5d60d27d33a`.
- Fixed commit = тег `v0.4.0`: `fac76df42c5639c89275c23178bfed3f1239a18e`; хеші вписано окремим commit після тегу.
- Репозиторій: https://github.com/chudj4ck/Laboratory-Work-1-Web-System-Setup-and-Extension (гілка `lab/4-authorization`, тег `v0.4.0`).
- Невиконано: A-08b (обрано A-08a), A-11 і розділ відмінного рівня.

## Використання ШІ
Використано Claude як асистента для плану роботи, коду авторизації й тестів; результати перевірено самостійно
запуском застосунку, ручними запитами та автотестами. Паролі й cookie не передавались.
