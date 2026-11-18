window.SecureLabCsrf = (() => {
  const headerName = "X-CSRF-TOKEN";
  const unsafeMethods = new Set(["POST", "PUT", "PATCH", "DELETE"]);
  let token = null;
  let pending = null;

  async function getToken() {
    if (token) return token;
    pending ??= fetch("/api/auth/csrf-token", {
      credentials: "same-origin",
      headers: { Accept: "application/json" }
    })
      .then(async response => {
        if (!response.ok) throw new Error(`CSRF token: ${response.status}`);
        token = (await response.json()).token;
        return token;
      })
      .finally(() => { pending = null; });
    return pending;
  }

  async function mutate(path, options = {}) {
    const url = new URL(path, location.origin);
    if (url.origin !== location.origin) throw new Error("CSRF token is same-origin only.");
    const method = (options.method ?? "GET").toUpperCase();
    if (!unsafeMethods.has(method)) {
      return fetch(url, { ...options, credentials: "same-origin" });
    }
    const headers = new Headers(options.headers ?? {});
    headers.set(headerName, await getToken());
    return fetch(url, { ...options, method, headers, credentials: "same-origin" });
  }

  function reset() {
    token = null;
    pending = null;
  }

  return { mutate, reset };
})();
