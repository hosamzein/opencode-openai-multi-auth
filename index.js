import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import { homedir } from "node:os";
import path from "node:path";

const OAUTH_AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize";
const OAUTH_TOKEN_URL = "https://auth.openai.com/oauth/token";
const REDIRECT_URI = "http://localhost:1455/callback";
const DEFAULT_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const SCOPE = "openid profile email offline_access";
const OPENAI_PROVIDER_ID = "openai";
const DEFAULT_STRATEGY = "sticky";
const DEFAULT_RATE_LIMIT_COOLDOWN_MS = 60_000;
const REFRESH_BUFFER_MS = 60_000;

function base64Url(buffer) {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function createPkcePair() {
  const verifier = base64Url(crypto.randomBytes(64));
  const challenge = base64Url(crypto.createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

function decodeJwt(token) {
  if (!token || typeof token !== "string" || !token.includes(".")) return null;
  try {
    const payload = token.split(".")[1];
    return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

function getByPath(obj, pathKey) {
  if (!obj || typeof obj !== "object") return undefined;
  return pathKey.split(".").reduce((acc, key) => (acc && acc[key] !== undefined ? acc[key] : undefined), obj);
}

function isOAuthAuth(auth) {
  return !!auth && auth.type === "oauth" && typeof auth.refresh === "string";
}

function resolveConfigDir() {
  if (process.env.OPENCODE_CONFIG_DIR) return process.env.OPENCODE_CONFIG_DIR;
  return path.join(homedir(), ".config", "opencode");
}

function resolveAccountsPath() {
  return path.join(resolveConfigDir(), "openai-accounts.json");
}

function parseRetryAfterMs(headers) {
  const value = headers.get("retry-after");
  if (!value) return null;
  const asInt = Number.parseInt(value, 10);
  if (Number.isFinite(asInt)) return Math.max(0, asInt * 1000);
  const asDate = Date.parse(value);
  if (Number.isFinite(asDate)) return Math.max(0, asDate - Date.now());
  return null;
}

function normalizeStrategy(value) {
  if (value === "round-robin") return "round-robin";
  return DEFAULT_STRATEGY;
}

function readConfigFile() {
  const configPath = path.join(resolveConfigDir(), "openai-multi.json");
  return fs
    .readFile(configPath, "utf8")
    .then((raw) => JSON.parse(raw))
    .catch(() => ({}));
}

function accountMetaFromAuth(auth) {
  const claims = decodeJwt(auth.access) || {};
  const accountId =
    auth.accountId ||
    getByPath(claims, "https://api.openai.com/auth.chatgpt_account_id") ||
    getByPath(claims, "chatgpt_account_id") ||
    crypto.createHash("sha1").update(auth.refresh).digest("hex");
  const email =
    getByPath(claims, "https://api.openai.com/profile.email") ||
    getByPath(claims, "email") ||
    null;
  const clientId = getByPath(claims, "client_id") || DEFAULT_CLIENT_ID;
  return { accountId, email, clientId };
}

async function loadPool(filePath) {
  try {
    const raw = await fs.readFile(filePath, "utf8");
    const parsed = JSON.parse(raw);
    if (!parsed || !Array.isArray(parsed.accounts)) {
      return { version: 1, strategy: DEFAULT_STRATEGY, cursor: 0, accounts: [] };
    }
    return {
      version: 1,
      strategy: normalizeStrategy(parsed.strategy),
      cursor: Number.isInteger(parsed.cursor) ? parsed.cursor : 0,
      accounts: parsed.accounts.map((account) => ({
        accountId: account.accountId,
        email: account.email ?? null,
        refresh: account.refresh,
        access: account.access ?? null,
        expires: Number.isFinite(account.expires) ? account.expires : 0,
        clientId: account.clientId || DEFAULT_CLIENT_ID,
        enabled: account.enabled !== false,
        lastUsed: Number.isFinite(account.lastUsed) ? account.lastUsed : 0,
        rateLimitedUntil: Number.isFinite(account.rateLimitedUntil) ? account.rateLimitedUntil : 0
      }))
    };
  } catch {
    return { version: 1, strategy: DEFAULT_STRATEGY, cursor: 0, accounts: [] };
  }
}

async function savePool(filePath, pool) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(pool, null, 2));
}

function upsertAccountFromAuth(pool, auth) {
  const meta = accountMetaFromAuth(auth);
  const now = Date.now();
  const index = pool.accounts.findIndex((account) => account.accountId === meta.accountId);
  const updated = {
    accountId: meta.accountId,
    email: meta.email,
    refresh: auth.refresh,
    access: auth.access,
    expires: auth.expires ?? now,
    clientId: meta.clientId,
    enabled: true,
    lastUsed: index >= 0 ? pool.accounts[index].lastUsed : 0,
    rateLimitedUntil: index >= 0 ? pool.accounts[index].rateLimitedUntil : 0
  };
  if (index >= 0) {
    pool.accounts[index] = updated;
  } else {
    pool.accounts.push(updated);
  }
}

function findAvailableAccountIndexes(pool, now) {
  const indexes = [];
  for (let i = 0; i < pool.accounts.length; i += 1) {
    const account = pool.accounts[i];
    if (!account?.enabled) continue;
    if (account.rateLimitedUntil && account.rateLimitedUntil > now) continue;
    indexes.push(i);
  }
  return indexes;
}

function pickAccountIndex(pool, availableIndexes, strategy, usePidOffset) {
  if (availableIndexes.length === 0) return -1;
  if (strategy === "round-robin") {
    const index = availableIndexes[pool.cursor % availableIndexes.length];
    pool.cursor = (pool.cursor + 1) % Math.max(1, availableIndexes.length);
    return index;
  }
  if (usePidOffset && availableIndexes.length > 1) {
    const offset = process.pid % availableIndexes.length;
    const index = availableIndexes[(pool.cursor + offset) % availableIndexes.length];
    return index;
  }
  const current = availableIndexes[pool.cursor % availableIndexes.length];
  return current;
}

async function refreshAccessToken(account) {
  const response = await fetch(OAUTH_TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      grant_type: "refresh_token",
      refresh_token: account.refresh,
      client_id: account.clientId || DEFAULT_CLIENT_ID,
      redirect_uri: REDIRECT_URI
    })
  });
  if (!response.ok) {
    return false;
  }
  const body = await response.json();
  if (!body?.access_token) return false;
  account.access = body.access_token;
  if (body.refresh_token) account.refresh = body.refresh_token;
  account.expires = Date.now() + (body.expires_in ? body.expires_in * 1000 : 3600_000);
  return true;
}

async function ensureValidToken(account) {
  const now = Date.now();
  if (account.access && account.expires && account.expires - REFRESH_BUFFER_MS > now) {
    return true;
  }
  return refreshAccessToken(account);
}

async function exchangeAuthorizationCode(code, verifier, clientId) {
  const response = await fetch(OAUTH_TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      grant_type: "authorization_code",
      code,
      client_id: clientId || DEFAULT_CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier
    })
  });
  if (!response.ok) return null;
  const body = await response.json();
  if (!body?.access_token || !body?.refresh_token) return null;
  return {
    type: "success",
    access: body.access_token,
    refresh: body.refresh_token,
    expires: Date.now() + (body.expires_in ? body.expires_in * 1000 : 3600_000)
  };
}

function startOAuthListener(state) {
  let resolveCode;
  let resolveFailed;
  const codePromise = new Promise((resolve, reject) => {
    resolveCode = resolve;
    resolveFailed = reject;
  });
  const server = http.createServer((req, res) => {
    const url = new URL(req.url || "/", REDIRECT_URI);
    if (url.pathname !== "/callback") {
      res.writeHead(404).end("Not found");
      return;
    }
    const incomingState = url.searchParams.get("state");
    const code = url.searchParams.get("code");
    if (!incomingState || incomingState !== state || !code) {
      res.writeHead(400).end("Invalid callback");
      resolveFailed(new Error("Invalid OAuth callback"));
      return;
    }
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end("<html><body><h2>OpenCode auth received. You can close this tab.</h2></body></html>");
    resolveCode(code);
  });
  server.listen(1455, "127.0.0.1");
  return {
    waitForCode: () => codePromise.finally(() => server.close()),
    close: () => server.close()
  };
}

function buildAuthorizeUrl({ state, challenge, clientId }) {
  const url = new URL(OAUTH_AUTHORIZE_URL);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", clientId || DEFAULT_CLIENT_ID);
  url.searchParams.set("redirect_uri", REDIRECT_URI);
  url.searchParams.set("scope", SCOPE);
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}

function requestLooksReplayable(init) {
  if (!init || init.body == null) return true;
  const body = init.body;
  return typeof body === "string" || body instanceof URLSearchParams || body instanceof Uint8Array || ArrayBuffer.isView(body) || body instanceof ArrayBuffer;
}

function isRateLimitedStatus(status) {
  return status === 429 || status === 503 || status === 529;
}

function isOpenAiHttpRequest(input) {
  const raw = typeof input === "string" ? input : input?.url;
  if (!raw) return false;
  return raw.includes("api.openai.com");
}

export const OpenAIMultiAccountPlugin = async () => {
  const accountsPath = resolveAccountsPath();
  const userConfig = await readConfigFile();
  const strategy = normalizeStrategy(userConfig.account_selection_strategy);
  const pidOffsetEnabled = userConfig.pid_offset_enabled === true;
  const fallbackCooldownMs =
    Number.isFinite(userConfig.rate_limit_cooldown_seconds) && userConfig.rate_limit_cooldown_seconds > 0
      ? userConfig.rate_limit_cooldown_seconds * 1000
      : DEFAULT_RATE_LIMIT_COOLDOWN_MS;

  const pool = await loadPool(accountsPath);
  pool.strategy = strategy;
  let saveQueue = Promise.resolve();

  const queueSave = () => {
    saveQueue = saveQueue.then(() => savePool(accountsPath, pool)).catch(() => {});
  };

  return {
    auth: {
      provider: OPENAI_PROVIDER_ID,
      loader: async (getAuth) => {
        const currentAuth = await getAuth();
        if (isOAuthAuth(currentAuth)) {
          upsertAccountFromAuth(pool, currentAuth);
          queueSave();
        }
        return {
          apiKey: "",
          async fetch(input, init) {
            if (!isOpenAiHttpRequest(input)) {
              return fetch(input, init);
            }
            if (!requestLooksReplayable(init)) {
              const now = Date.now();
              const availableIndexes = findAvailableAccountIndexes(pool, now);
              if (availableIndexes.length === 0) {
                throw new Error("No available OpenAI account. All accounts are in cooldown.");
              }
              const chosen = pickAccountIndex(pool, availableIndexes, strategy, pidOffsetEnabled);
              const account = pool.accounts[chosen];
              const ok = await ensureValidToken(account);
              if (!ok) {
                throw new Error("Unable to refresh OpenAI token for selected account.");
              }
              const headers = new Headers(init?.headers || {});
              headers.set("authorization", `Bearer ${account.access}`);
              const response = await fetch(input, { ...init, headers });
              account.lastUsed = Date.now();
              queueSave();
              return response;
            }

            const maxAttempts = Math.max(1, pool.accounts.filter((a) => a.enabled !== false).length);
            const attempted = new Set();
            let lastRateLimitedError = null;

            for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
              const now = Date.now();
              const availableIndexes = findAvailableAccountIndexes(pool, now).filter((i) => !attempted.has(i));
              if (availableIndexes.length === 0) break;
              const chosen = pickAccountIndex(pool, availableIndexes, strategy, pidOffsetEnabled);
              if (chosen < 0) break;
              attempted.add(chosen);
              const account = pool.accounts[chosen];

              const valid = await ensureValidToken(account);
              if (!valid) {
                account.enabled = false;
                queueSave();
                continue;
              }

              const headers = new Headers(init?.headers || {});
              headers.set("authorization", `Bearer ${account.access}`);
              let response = await fetch(input, { ...init, headers });

              if (response.status === 401) {
                const refreshed = await refreshAccessToken(account);
                if (refreshed) {
                  headers.set("authorization", `Bearer ${account.access}`);
                  response = await fetch(input, { ...init, headers });
                } else {
                  account.enabled = false;
                  queueSave();
                  continue;
                }
              }

              if (isRateLimitedStatus(response.status)) {
                const retryAfterMs = parseRetryAfterMs(response.headers);
                const cooldownMs = retryAfterMs ?? fallbackCooldownMs;
                account.rateLimitedUntil = Date.now() + cooldownMs;
                queueSave();
                lastRateLimitedError = `Account ${account.email ?? account.accountId} rate-limited (${response.status})`;
                continue;
              }

              account.rateLimitedUntil = 0;
              account.lastUsed = Date.now();
              queueSave();
              return response;
            }

            if (lastRateLimitedError) {
              throw new Error(`${lastRateLimitedError}. All accounts are currently rate-limited.`);
            }
            throw new Error("No usable OpenAI account found. Re-run `opencode auth login openai` to add/refresh accounts.");
          }
        };
      },
      methods: [
        {
          type: "oauth",
          label: "OpenAI OAuth (add or refresh account)",
          async authorize() {
            const { verifier, challenge } = createPkcePair();
            const state = base64Url(crypto.randomBytes(24));
            const listener = startOAuthListener(state);
            const latestKnownClientId =
              pool.accounts.find((account) => account.clientId)?.clientId || DEFAULT_CLIENT_ID;
            const url = buildAuthorizeUrl({ state, challenge, clientId: latestKnownClientId });
            return {
              url,
              instructions:
                "Open this URL, sign in, and approve access. Run this command multiple times to add multiple OpenAI accounts.",
              method: "auto",
              async callback() {
                try {
                  const code = await listener.waitForCode();
                  const result = await exchangeAuthorizationCode(code, verifier, latestKnownClientId);
                  return result ?? { type: "failed" };
                } catch {
                  return { type: "failed" };
                } finally {
                  listener.close();
                }
              }
            };
          }
        }
      ]
    }
  };
};

export default OpenAIMultiAccountPlugin;
