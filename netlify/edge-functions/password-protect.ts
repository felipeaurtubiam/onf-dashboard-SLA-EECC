const COOKIE_NAME = "onf_norte_session";
const MAX_AGE_SECONDS = 60 * 60 * 24;
const CONFIG_MESSAGE =
  "This page is not yet configured. The site owner needs to set the PROTECTED_PAGE_PASSWORD environment variable.";

declare const Netlify: {
  env: {
    get(name: string): string | undefined;
  };
};

async function sha256Hex(value: string): Promise<string> {
  const data = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(hash)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function timingSafeEqual(a: string, b: string): boolean {
  const left = new TextEncoder().encode(a);
  const right = new TextEncoder().encode(b);
  const length = Math.max(left.length, right.length);
  let diff = left.length ^ right.length;

  for (let index = 0; index < length; index += 1) {
    diff |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }

  return diff === 0;
}

function getPassword(): string | undefined {
  return Netlify.env.get("PROTECTED_PAGE_PASSWORD") || undefined;
}

function getCookie(req: Request, name: string): string | undefined {
  const header = req.headers.get("cookie");
  if (!header) return undefined;

  return header
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`))
    ?.slice(name.length + 1);
}

async function createSessionValue(passwordHash: string): Promise<string> {
  const expires = Math.floor(Date.now() / 1000) + MAX_AGE_SECONDS;
  const signature = await sha256Hex(`${expires}.${passwordHash}`);
  return `${expires}.${signature}`;
}

async function hasValidSession(req: Request, passwordHash: string): Promise<boolean> {
  const cookie = getCookie(req, COOKIE_NAME);
  if (!cookie) return false;

  const [expiresRaw, signature] = cookie.split(".");
  const expires = Number(expiresRaw);
  if (!Number.isFinite(expires) || expires < Math.floor(Date.now() / 1000) || !signature) {
    return false;
  }

  const expected = await sha256Hex(`${expires}.${passwordHash}`);
  return timingSafeEqual(signature, expected);
}

function htmlPage(content: string, status = 200): Response {
  return new Response(content, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function passwordForm(error = ""): Response {
  return htmlPage(`<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<title>Acceso protegido - ON*NET FIBRA</title>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<style>
  :root{--morado:#201751;--cyan:#06EFFF;--negro:#191919;--bg:#FFFFFF;--gris-suave:#F4F5F8;--gris-borde:#E2E4EC;--crit:#C62828;--texto:#191919;--texto-suave:#5A5E72}
  *{box-sizing:border-box}
  html,body{margin:0;min-height:100%;background:var(--bg);color:var(--texto);font-family:'Open Sans',-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;font-size:13px}
  body{min-height:100vh;background:linear-gradient(to right,var(--cyan) 0,var(--cyan) 4px,transparent 4px),var(--bg);display:flex;align-items:center;justify-content:center;padding:28px}
  .access{width:min(440px,100%);border:1px solid var(--gris-borde);border-radius:6px;background:#fff;box-shadow:0 16px 40px rgba(32,23,81,.12);overflow:hidden}
  .access-head{background:var(--morado);color:#fff;padding:20px 24px;position:relative}
  .access-head::before{content:"*";position:absolute;left:12px;top:7px;color:var(--cyan);font-size:24px;font-weight:800}
  h1{margin:0 0 4px 20px;font-size:20px;letter-spacing:.4px}
  h1 span{color:var(--cyan)}
  .sub{margin-left:20px;color:#cdd0e0;font-size:12px}
  form{padding:22px 24px 24px;display:flex;flex-direction:column;gap:12px}
  label{font-size:10.5px;color:var(--texto-suave);text-transform:uppercase;letter-spacing:.6px;font-weight:700}
  input{width:100%;border:1px solid var(--gris-borde);border-radius:4px;padding:10px 12px;font:inherit;color:var(--texto)}
  input:focus{outline:2px solid var(--cyan);outline-offset:-1px;border-color:var(--cyan)}
  button{border:0;border-radius:4px;background:var(--morado);color:#fff;font:inherit;font-weight:700;padding:10px 14px;cursor:pointer}
  button:focus{outline:2px solid var(--cyan);outline-offset:2px}
  .error{margin:0;color:var(--crit);font-weight:700}
</style>
</head>
<body>
  <main class="access">
    <div class="access-head">
      <h1>Control de <span>SLA</span></h1>
      <div class="sub">Acceso protegido</div>
    </div>
    <form method="post">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" autofocus required/>
      ${error ? `<p class="error">${error}</p>` : ""}
      <button type="submit">Ingresar</button>
    </form>
  </main>
</body>
</html>`, error ? 401 : 200);
}

function configurationMissing(): Response {
  return htmlPage(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Page not configured</title>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<style>
  :root{--morado:#201751;--cyan:#06EFFF;--gris-borde:#E2E4EC;--texto:#191919}
  *{box-sizing:border-box}
  html,body{margin:0;min-height:100%;font-family:'Open Sans',-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;color:var(--texto)}
  body{min-height:100vh;background:linear-gradient(to right,var(--cyan) 0,var(--cyan) 4px,transparent 4px);display:flex;align-items:center;justify-content:center;padding:28px}
  .message{width:min(620px,100%);border:1px solid var(--gris-borde);border-radius:6px;background:#fff;padding:24px;border-top:4px solid var(--morado)}
  p{margin:0;font-size:15px;line-height:1.5}
</style>
</head>
<body><main class="message"><p>${CONFIG_MESSAGE}</p></main></body>
</html>`, 503);
}

export default async (req: Request) => {
  const url = new URL(req.url);
  const password = getPassword();

  if (url.searchParams.has("logout")) {
    const redirect = new URL(url);
    redirect.searchParams.delete("logout");
    return new Response(null, {
      status: 303,
      headers: {
        location: redirect.toString(),
        "set-cookie": `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`,
        "cache-control": "no-store",
      },
    });
  }

  if (!password) {
    return configurationMissing();
  }

  const passwordHash = await sha256Hex(password);

  if (req.method === "POST") {
    const form = await req.formData();
    const submitted = String(form.get("password") || "");
    const submittedHash = await sha256Hex(submitted);

    if (!timingSafeEqual(submittedHash, passwordHash)) {
      return passwordForm("Password incorrecto. Intenta nuevamente.");
    }

    const session = await createSessionValue(passwordHash);
    return new Response(null, {
      status: 303,
      headers: {
        location: url.pathname || "/",
        "set-cookie": `${COOKIE_NAME}=${session}; Path=/; Max-Age=${MAX_AGE_SECONDS}; HttpOnly; Secure; SameSite=Strict`,
        "cache-control": "no-store",
      },
    });
  }

  if (req.method === "GET" || req.method === "HEAD") {
    if (await hasValidSession(req, passwordHash)) {
      return;
    }

    return passwordForm();
  }

  return new Response("Method not allowed", {
    status: 405,
    headers: {
      allow: "GET, HEAD, POST",
      "cache-control": "no-store",
    },
  });
};
