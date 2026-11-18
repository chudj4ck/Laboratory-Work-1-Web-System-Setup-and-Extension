const sessionState = document.querySelector("#session-state");
const logoutResult = document.querySelector("#logout-result");
const registerResult = document.querySelector("#register-result");
const loginResult = document.querySelector("#login-result");
const profileMessage = document.querySelector("#profile-message");
const profileList = document.querySelector("#profile");
const incidentResult = document.querySelector("#incident-result");
const incidentList = document.querySelector("#incident");

async function apiFetch(path, options = {}) {
  const url = new URL(path, location.origin);
  if (url.origin !== location.origin) {
    throw new Error("Потрібна адреса цього застосунку.");
  }
  return fetch(url, { ...options, credentials: "same-origin" });
}

function postJson(path, body) {
  return apiFetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
}

function isJson(response) {
  return (response.headers.get("Content-Type") ?? "").includes("json");
}

function renderFields(list, fields) {
  list.replaceChildren();
  for (const [name, value] of fields) {
    const term = document.createElement("dt");
    term.textContent = name;
    const description = document.createElement("dd");
    description.textContent = value;
    list.append(term, description);
  }
}

function clearProfile() {
  profileList.replaceChildren();
}

function clearIncident() {
  incidentResult.textContent = "";
  incidentList.replaceChildren();
}

function showState(state) {
  const labels = {
    "signed-in": "Сеанс активний",
    "anonymous": "Не ввійшли",
    "unknown": "Стан невідомий (помилка перевірки)"
  };
  sessionState.textContent = labels[state];
}

async function refreshSessionState() {
  try {
    const response = await apiFetch("/api/auth/session-check");
    if (response.status === 204) {
      showState("signed-in");
    } else if (response.status === 401) {
      showState("anonymous");
    } else {
      showState("unknown");
    }
  } catch {
    showState("unknown");
  }
}

async function loadProfile() {
  try {
    const response = await apiFetch("/api/me");
    if (response.status === 401) {
      clearProfile();
      profileMessage.textContent = "Профіль: 401 — не ввійшли.";
      showState("anonymous");
      return;
    }
    if (!response.ok || !isJson(response)) {
      clearProfile();
      profileMessage.textContent = `Профіль недоступний: ${response.status}.`;
      return;
    }
    const profile = await response.json();
    profileMessage.textContent = `Профіль: ${response.status}.`;
    renderFields(profileList, [
      ["Ім’я користувача", profile.userName],
      ["Ролі", (profile.roles ?? []).join(", ")],
      ["Ідентифікатор", profile.id]
    ]);
    showState("signed-in");
  } catch {
    clearProfile();
    profileMessage.textContent = "Профіль недоступний: помилка мережі.";
  }
}

document.querySelector("#register-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const request = {
    userName: data.get("userName"),
    email: data.get("email"),
    displayName: data.get("displayName"),
    password: data.get("password")
  };
  try {
    const response = await postJson("/api/auth/register", request);
    registerResult.textContent = response.status === 201
      ? "Реєстрація успішна: 201. Тепер увійдіть у формі «Вхід»."
      : `Реєстрацію відхилено: ${response.status}.`;
  } catch {
    registerResult.textContent = "Реєстрація: помилка мережі.";
  } finally {
    form.elements.password.value = "";
  }
});

document.querySelector("#login-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const request = { userName: data.get("userName"), password: data.get("password") };
  try {
    const response = await postJson("/api/auth/login", request);
    loginResult.textContent = `Вхід: ${response.status}.`;
    if (response.status === 204) {
      SecureLabCsrf.reset();
      await loadProfile();
    } else {
      clearProfile();
      profileMessage.textContent = "";
    }
  } catch {
    loginResult.textContent = "Вхід: помилка мережі.";
  } finally {
    form.elements.password.value = "";
    await refreshSessionState();
  }
});

document.querySelector("#load-profile").addEventListener("click", loadProfile);

document.querySelector("#incident-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const request = {
    title: data.get("title"),
    description: data.get("description"),
    severity: data.get("severity"),
    occurredAtUtc: new Date(data.get("occurredAt")).toISOString()
  };
  incidentList.replaceChildren();
  try {
    const response = await SecureLabCsrf.mutate("/api/incidents", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request)
    });
    if (response.status === 201 && isJson(response)) {
      const incident = await response.json();
      incidentResult.textContent = "Інцидент створено: 201.";
      renderFields(incidentList, [
        ["Назва", incident.title],
        ["Рівень", incident.severity],
        ["Статус", incident.status],
        ["Виник (UTC)", incident.occurredAtUtc],
        ["Створено (UTC)", incident.createdAtUtc]
      ]);
      form.reset();
    } else {
      incidentResult.textContent = `Помилка створення: ${response.status}.`;
      if (response.status === 401) {
        showState("anonymous");
      }
    }
  } catch {
    incidentResult.textContent = "Створення: помилка мережі.";
  }
});

document.querySelector("#logout").addEventListener("click", async () => {
  try {
    const response = await SecureLabCsrf.mutate("/api/auth/logout", { method: "POST" });
    logoutResult.textContent = `Вихід: ${response.status}.`;
    if (response.ok) SecureLabCsrf.reset();
    if (response.status === 204 || response.status === 401) {
      clearProfile();
      clearIncident();
      loginResult.textContent = "";
      registerResult.textContent = "";
      await loadProfile();
    }
  } catch {
    logoutResult.textContent = "Вихід: помилка мережі.";
  } finally {
    await refreshSessionState();
  }
});

refreshSessionState();
