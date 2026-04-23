import { createServer } from "node:http";
import { readFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { randomBytes, randomUUID, scryptSync, timingSafeEqual } from "node:crypto";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const publicRoot = __dirname;
const dataDir = join(__dirname, "data");
const dbPath = join(dataDir, "game.sqlite");
const port = Number(process.env.PORT || 3000);

await mkdir(dataDir, { recursive: true });

const db = new DatabaseSync(dbPath);
db.exec("PRAGMA foreign_keys = ON;");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    name TEXT NOT NULL,
    score INTEGER NOT NULL,
    level INTEGER NOT NULL,
    combo INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
  );
`);
migrateDatabase();

const createUser = db.prepare(`
  INSERT INTO users (username, password_hash, salt)
  VALUES (?, ?, ?)
`);
const findUserByName = db.prepare(`
  SELECT id, username, password_hash AS passwordHash, salt
  FROM users
  WHERE username = ?
`);
const findUserBySession = db.prepare(`
  SELECT users.id, users.username
  FROM sessions
  JOIN users ON users.id = sessions.user_id
  WHERE sessions.id = ? AND sessions.expires_at > ?
`);
const createSession = db.prepare(`
  INSERT INTO sessions (id, user_id, expires_at)
  VALUES (?, ?, ?)
`);
const deleteSession = db.prepare("DELETE FROM sessions WHERE id = ?");
const deleteExpiredSessions = db.prepare("DELETE FROM sessions WHERE expires_at <= ?");
const insertScore = db.prepare(`
  INSERT INTO scores (user_id, name, score, level, combo)
  VALUES (?, ?, ?, ?, ?)
`);
const listScores = db.prepare(`
  SELECT
    scores.id,
    COALESCE(users.username, scores.name) AS name,
    scores.score,
    scores.level,
    scores.combo,
    scores.created_at AS createdAt
  FROM scores
  LEFT JOIN users ON users.id = scores.user_id
  WHERE scores.user_id IS NOT NULL
  ORDER BY scores.score DESC, scores.level DESC, scores.combo DESC, scores.id ASC
  LIMIT ?
`);
const getPersonalBest = db.prepare(`
  SELECT id, score, level, combo, created_at AS createdAt
  FROM scores
  WHERE user_id = ?
  ORDER BY score DESC, level DESC, combo DESC, id ASC
  LIMIT 1
`);
const listPersonalScores = db.prepare(`
  SELECT id, score, level, combo, created_at AS createdAt
  FROM scores
  WHERE user_id = ?
  ORDER BY created_at DESC, id DESC
  LIMIT ?
`);

const mimeTypes = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".ico", "image/x-icon"]
]);

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url || "/", `http://${request.headers.host}`);

    if (url.pathname === "/api/health" && request.method === "GET") {
      sendJson(response, 200, { ok: true });
      return;
    }

    if (url.pathname === "/api/auth/me" && request.method === "GET") {
      const user = getCurrentUser(request);
      sendJson(response, 200, { user });
      return;
    }

    if (url.pathname === "/api/auth/register" && request.method === "POST") {
      const body = await readJson(request);
      const username = sanitizeUsername(body.username);
      const password = String(body.password || "");

      if (!username || password.length < 6) {
        sendJson(response, 400, { error: "用户名不能为空，密码至少 6 位" });
        return;
      }

      if (findUserByName.get(username)) {
        sendJson(response, 409, { error: "用户名已被注册" });
        return;
      }

      const { hash, salt } = hashPassword(password);
      const result = createUser.run(username, hash, salt);
      const user = { id: Number(result.lastInsertRowid), username };
      issueSession(response, user.id);
      sendJson(response, 201, { user });
      return;
    }

    if (url.pathname === "/api/auth/login" && request.method === "POST") {
      const body = await readJson(request);
      const username = sanitizeUsername(body.username);
      const password = String(body.password || "");
      const userRecord = username ? findUserByName.get(username) : null;

      if (!userRecord || !verifyPassword(password, userRecord.passwordHash, userRecord.salt)) {
        sendJson(response, 401, { error: "用户名或密码不正确" });
        return;
      }

      issueSession(response, userRecord.id);
      sendJson(response, 200, { user: { id: userRecord.id, username: userRecord.username } });
      return;
    }

    if (url.pathname === "/api/auth/logout" && request.method === "POST") {
      const sessionId = getSessionId(request);
      if (sessionId) deleteSession.run(sessionId);
      sendJson(response, 200, { ok: true }, clearSessionCookie());
      return;
    }

    if (url.pathname === "/api/scores" && request.method === "GET") {
      const limit = clampInteger(url.searchParams.get("limit"), 1, 50, 10);
      sendJson(response, 200, { scores: listScores.all(limit) });
      return;
    }

    if (url.pathname === "/api/scores" && request.method === "POST") {
      const user = getCurrentUser(request);
      if (!user) {
        sendJson(response, 401, { error: "请先登录再保存分数" });
        return;
      }

      const body = await readJson(request);
      const score = clampInteger(body.score, 0, 1_000_000, 0);
      const level = clampInteger(body.level, 1, 999, 1);
      const combo = clampInteger(body.combo, 0, 9999, 0);

      if (score <= 0) {
        sendJson(response, 400, { error: "分数必须大于 0" });
        return;
      }

      const result = insertScore.run(user.id, user.username, score, level, combo);
      sendJson(response, 201, {
        score: { id: result.lastInsertRowid, name: user.username, score, level, combo }
      });
      return;
    }

    if (url.pathname === "/api/me/scores" && request.method === "GET") {
      const user = getCurrentUser(request);
      if (!user) {
        sendJson(response, 401, { error: "请先登录" });
        return;
      }

      const limit = clampInteger(url.searchParams.get("limit"), 1, 50, 10);
      sendJson(response, 200, {
        best: getPersonalBest.get(user.id) || null,
        scores: listPersonalScores.all(user.id, limit)
      });
      return;
    }

    if (url.pathname.startsWith("/api/")) {
      sendJson(response, 404, { error: "接口不存在" });
      return;
    }

    await serveStatic(url.pathname, response);
  } catch (error) {
    console.error(error);
    sendJson(response, 500, { error: "服务器出错了" });
  }
});

deleteExpiredSessions.run(Date.now());

server.listen(port, () => {
  console.log(`星光快递已启动: http://localhost:${port}`);
  console.log(`数据库位置: ${dbPath}`);
});

async function serveStatic(pathname, response) {
  const requestedPath = pathname === "/" ? "/index.html" : decodeURIComponent(pathname);
  const safePath = normalize(requestedPath).replace(/^(\.\.[/\\])+/, "");
  const filePath = join(publicRoot, safePath);

  if (!filePath.startsWith(publicRoot) || !existsSync(filePath)) {
    response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    response.end("Not found");
    return;
  }

  const data = await readFile(filePath);
  response.writeHead(200, {
    "content-type": mimeTypes.get(extname(filePath)) || "application/octet-stream"
  });
  response.end(data);
}

function sendJson(response, status, payload, extraHeaders = {}) {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    ...extraHeaders
  });
  response.end(JSON.stringify(payload));
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    let raw = "";
    request.on("data", chunk => {
      raw += chunk;
      if (raw.length > 20_000) {
        request.destroy();
        reject(new Error("Request body too large"));
      }
    });
    request.on("end", () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch (error) {
        reject(error);
      }
    });
    request.on("error", reject);
  });
}

function clampInteger(value, min, max, fallback) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, parsed));
}

function sanitizeUsername(value) {
  const username = String(value || "")
    .replace(/[^\w\u4e00-\u9fa5-]/g, "")
    .trim()
    .slice(0, 12);
  return username;
}

function hashPassword(password, salt = randomBytes(16).toString("hex")) {
  return {
    salt,
    hash: scryptSync(password, salt, 64).toString("hex")
  };
}

function verifyPassword(password, expectedHash, salt) {
  const actual = Buffer.from(hashPassword(password, salt).hash, "hex");
  const expected = Buffer.from(expectedHash, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function issueSession(response, userId) {
  const sessionId = randomUUID();
  const expiresAt = Date.now() + 1000 * 60 * 60 * 24 * 30;
  createSession.run(sessionId, userId, expiresAt);
  response.setHeader("set-cookie", makeSessionCookie(sessionId, expiresAt));
}

function getCurrentUser(request) {
  const sessionId = getSessionId(request);
  if (!sessionId) return null;
  const user = findUserBySession.get(sessionId, Date.now());
  return user ? { id: user.id, username: user.username } : null;
}

function getSessionId(request) {
  const cookie = request.headers.cookie || "";
  const match = cookie.match(/(?:^|;\s*)star_session=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : "";
}

function makeSessionCookie(sessionId, expiresAt) {
  return [
    `star_session=${encodeURIComponent(sessionId)}`,
    "HttpOnly",
    "SameSite=Lax",
    "Path=/",
    `Expires=${new Date(expiresAt).toUTCString()}`
  ].join("; ");
}

function clearSessionCookie() {
  return {
    "set-cookie": "star_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
  };
}

function migrateDatabase() {
  const columns = db.prepare("PRAGMA table_info(scores)").all();
  if (!columns.some(column => column.name === "user_id")) {
    db.exec("ALTER TABLE scores ADD COLUMN user_id INTEGER");
  }
}
