const express = require('express')
const cors = require('cors')
const bcrypt = require('bcryptjs')
const path = require('node:path')
const fs = require('node:fs/promises')
const os = require('node:os')
const crypto = require('node:crypto')

const PORT = Number(process.env.PORT || 3000)
const DATABASE_URL = process.env.DATABASE_URL
const STORE_MODE = DATABASE_URL ? 'postgres' : 'file'
const SESSION_TTL_SECONDS = Number(process.env.SESSION_TTL_SECONDS || 120)

let pool = null
if (STORE_MODE === 'postgres') {
  // Só carrega pg quando for usar Postgres.
  const { Pool } = require('pg')
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: process.env.PGSSL === 'false' ? false : { rejectUnauthorized: false },
  })
}

function jsonError(res, status, message, extra) {
  const payload = { ok: false, error: message, ...(extra && typeof extra === 'object' ? extra : null) }
  return res.status(status).json(payload)
}

function requireAdminKey(req, res, next) {
  const required = process.env.ADMIN_KEY
  if (!required) return next()
  const got = req.header('x-admin-key')
  if (!got || got !== required) return jsonError(res, 401, 'Unauthorized')
  return next()
}

function getAccountsFilePath() {
  const p = process.env.ACCOUNTS_FILE
  if (p) return p
  // Sempre usa um local gravável (em hosts/serverless o cwd pode ser read-only).
  // Observação: no modo file, os dados podem ser efêmeros após restart/redeploy.
  return path.join(os.tmpdir(), 'accounts.json')
}

function getSessionsFilePath() {
  const p = process.env.SESSIONS_FILE
  if (p) return p
  return path.join(os.tmpdir(), 'sessions.json')
}

async function readJsonIfExists(filePath) {
  try {
    const content = await fs.readFile(filePath, 'utf-8')
    return content ? JSON.parse(content) : null
  } catch (e) {
    if (e && e.code === 'ENOENT') return null
    throw e
  }
}

async function writeJsonAtomic(filePath, data) {
  const dir = path.dirname(filePath)
  await fs.mkdir(dir, { recursive: true })
  const tmp = `${filePath}.tmp`
  await fs.writeFile(tmp, JSON.stringify(data, null, 2), 'utf-8')
  await fs.rename(tmp, filePath)
}

async function fileCreateAccount(username, passwordHash) {
  const filePath = getAccountsFilePath()
  const data = (await readJsonIfExists(filePath)) ?? { accounts: {} }
  if (!data.accounts || typeof data.accounts !== 'object') data.accounts = {}
  if (data.accounts[username]) return { ok: false, status: 409, error: 'username ja existe' }
  data.accounts[username] = { password_hash: passwordHash, created_at: new Date().toISOString() }
  await writeJsonAtomic(filePath, data)
  return { ok: true }
}

async function fileGetPasswordHash(username) {
  const filePath = getAccountsFilePath()
  const data = (await readJsonIfExists(filePath)) ?? { accounts: {} }
  const row = data.accounts && typeof data.accounts === 'object' ? data.accounts[username] : null
  return row?.password_hash ?? null
}

function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex')
}

function isSessionExpired(lastSeenAtIso) {
  const t = Date.parse(String(lastSeenAtIso || ''))
  if (!Number.isFinite(t)) return true
  return Date.now() - t > SESSION_TTL_SECONDS * 1000
}

async function fileReadSessions() {
  const filePath = getSessionsFilePath()
  const data = (await readJsonIfExists(filePath)) ?? { activeByUser: {}, byToken: {} }
  if (!data.activeByUser || typeof data.activeByUser !== 'object') data.activeByUser = {}
  if (!data.byToken || typeof data.byToken !== 'object') data.byToken = {}
  return { filePath, data }
}

async function fileWriteSessions(filePath, data) {
  await writeJsonAtomic(filePath, data)
}

async function fileGetActiveSession(username) {
  const { filePath, data } = await fileReadSessions()
  const token = data.activeByUser[username]
  if (!token) return { session: null }
  const s = data.byToken[token]
  if (!s || s.username !== username || s.revoked_at) {
    delete data.activeByUser[username]
    await fileWriteSessions(filePath, data)
    return { session: null }
  }
  if (isSessionExpired(s.last_seen_at)) {
    s.revoked_at = new Date().toISOString()
    delete data.activeByUser[username]
    await fileWriteSessions(filePath, data)
    return { session: null }
  }
  return { session: { token, ...s } }
}

async function fileRevokeSessionToken(token) {
  const { filePath, data } = await fileReadSessions()
  const s = data.byToken[token]
  if (s && !s.revoked_at) {
    s.revoked_at = new Date().toISOString()
    if (data.activeByUser[s.username] === token) delete data.activeByUser[s.username]
    await fileWriteSessions(filePath, data)
  }
  return true
}

async function fileCreateSession(username, deviceId) {
  const { filePath, data } = await fileReadSessions()
  const token = generateSessionToken()
  const now = new Date().toISOString()
  data.byToken[token] = { username, device_id: deviceId || null, created_at: now, last_seen_at: now, revoked_at: null }
  data.activeByUser[username] = token
  await fileWriteSessions(filePath, data)
  return { token }
}

async function filePingSession(token) {
  const { filePath, data } = await fileReadSessions()
  const s = data.byToken[token]
  if (!s || s.revoked_at) return { ok: false, status: 401, error: 'sessao invalida' }
  if (isSessionExpired(s.last_seen_at)) {
    s.revoked_at = new Date().toISOString()
    if (data.activeByUser[s.username] === token) delete data.activeByUser[s.username]
    await fileWriteSessions(filePath, data)
    return { ok: false, status: 401, error: 'sessao expirada' }
  }
  s.last_seen_at = new Date().toISOString()
  data.activeByUser[s.username] = token
  await fileWriteSessions(filePath, data)
  return { ok: true, username: s.username }
}

async function ensureSchema() {
  if (STORE_MODE !== 'postgres') return
  await pool.query(`
    create table if not exists accounts (
      id bigserial primary key,
      username text not null unique,
      password_hash text not null,
      created_at timestamptz not null default now()
    );
  `)

  await pool.query(`
    create table if not exists sessions (
      token text primary key,
      username text not null references accounts(username) on delete cascade,
      device_id text,
      created_at timestamptz not null default now(),
      last_seen_at timestamptz not null default now(),
      revoked_at timestamptz
    );
  `)

  await pool.query(`
    create unique index if not exists sessions_one_active_per_user
    on sessions(username)
    where revoked_at is null;
  `)

  await pool.query(`create index if not exists sessions_username_idx on sessions(username);`)
  await pool.query(`create index if not exists sessions_last_seen_idx on sessions(last_seen_at);`)
}

const app = express()
app.use(
  cors({
    origin: '*',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-admin-key'],
  })
)
app.use(express.json({ limit: '2mb' }))

app.get('/health', async (_req, res) => {
  if (STORE_MODE === 'postgres') return res.json({ ok: true, mode: STORE_MODE })
  const filePath = getAccountsFilePath()
  let exists = true
  try {
    await fs.access(filePath)
  } catch {
    exists = false
  }
  return res.json({ ok: true, mode: STORE_MODE, accountsFile: filePath, accountsFileExists: exists })
})

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
})
app.use('/public', express.static(path.join(__dirname, 'public')))

app.post('/api/create', requireAdminKey, async (req, res) => {
  const username = String(req.body?.username ?? '').trim().toLowerCase()
  const password = String(req.body?.password ?? '')
  if (username.length < 3) return jsonError(res, 400, 'username invalido')
  if (password.length < 6) return jsonError(res, 400, 'senha deve ter no minimo 6 caracteres')

  const hash = await bcrypt.hash(password, 10)
  try {
    if (STORE_MODE === 'postgres') {
      await pool.query('insert into accounts (username, password_hash) values ($1, $2)', [username, hash])
    } else {
      const r = await fileCreateAccount(username, hash)
      if (!r.ok) return jsonError(res, r.status, r.error)
    }
    return res.json({ ok: true })
  } catch (e) {
    if (String(e?.code) === '23505') return jsonError(res, 409, 'username ja existe')
    console.error(e)
    return jsonError(res, 500, `erro ao criar conta: ${e?.message ?? String(e)}`)
  }
})

app.post('/api/login', async (req, res) => {
  const username = String(req.body?.username ?? '').trim().toLowerCase()
  const password = String(req.body?.password ?? '')
  if (!username || !password) return jsonError(res, 400, 'informe username e senha')

  try {
    let passwordHash = null
    if (STORE_MODE === 'postgres') {
      const r = await pool.query('select password_hash from accounts where username = $1', [username])
      if (r.rowCount === 0) return jsonError(res, 401, 'login invalido')
      passwordHash = r.rows[0].password_hash
    } else {
      passwordHash = await fileGetPasswordHash(username)
      if (!passwordHash) return jsonError(res, 401, 'login invalido')
    }

    const ok = await bcrypt.compare(password, passwordHash)
    if (!ok) return jsonError(res, 401, 'login invalido')

    const deviceId = String(req.body?.device_id ?? '').trim().slice(0, 120) || null
    const force = !!req.body?.force

    if (STORE_MODE === 'postgres') {
      const active = await pool.query(
        `
          select token, device_id, last_seen_at
          from sessions
          where username = $1
            and revoked_at is null
            and last_seen_at > (now() - ($2::int * interval '1 second'))
          order by last_seen_at desc
          limit 1
        `,
        [username, SESSION_TTL_SECONDS]
      )

      if (active.rowCount > 0 && !force) {
        return jsonError(res, 409, 'conta ja esta em uso em outro acesso', {
          code: 'SESSION_ACTIVE',
          active_device_id: active.rows[0].device_id ?? null,
          last_seen_at: active.rows[0].last_seen_at,
        })
      }

      await pool.query('begin')
      try {
        await pool.query('update sessions set revoked_at = now() where username = $1 and revoked_at is null', [username])
        const token = generateSessionToken()
        await pool.query('insert into sessions (token, username, device_id) values ($1, $2, $3)', [token, username, deviceId])
        await pool.query('commit')
        return res.json({ ok: true, token, ttl_seconds: SESSION_TTL_SECONDS })
      } catch (e) {
        await pool.query('rollback')
        if (String(e?.code) === '23505') {
          return jsonError(res, 409, 'conta ja esta em uso em outro acesso', { code: 'SESSION_ACTIVE' })
        }
        throw e
      }
    } else {
      const active = await fileGetActiveSession(username)
      if (active.session && !force) {
        return jsonError(res, 409, 'conta ja esta em uso em outro acesso', {
          code: 'SESSION_ACTIVE',
          active_device_id: active.session.device_id ?? null,
          last_seen_at: active.session.last_seen_at,
        })
      }
      if (active.session && force) await fileRevokeSessionToken(active.session.token)
      const created = await fileCreateSession(username, deviceId)
      return res.json({ ok: true, token: created.token, ttl_seconds: SESSION_TTL_SECONDS })
    }
  } catch (e) {
    console.error(e)
    return jsonError(res, 500, 'erro no login')
  }
})

function getBearerToken(req) {
  const raw = String(req.header('authorization') || '').trim()
  if (!raw) return null
  const lower = raw.toLowerCase()
  if (!lower.startsWith('bearer ')) return null
  const token = raw.slice(7).trim()
  return token || null
}

app.post('/api/session/ping', async (req, res) => {
  const token = getBearerToken(req)
  if (!token) return jsonError(res, 401, 'missing bearer token')

  try {
    if (STORE_MODE === 'postgres') {
      const r = await pool.query(
        `
          update sessions
          set last_seen_at = now()
          where token = $1
            and revoked_at is null
            and last_seen_at > (now() - ($2::int * interval '1 second'))
          returning username
        `,
        [token, SESSION_TTL_SECONDS]
      )
      if (r.rowCount === 0) return jsonError(res, 401, 'sessao invalida ou expirada', { code: 'SESSION_INVALID' })
      return res.json({ ok: true })
    } else {
      const r = await filePingSession(token)
      if (!r.ok) return jsonError(res, r.status, r.error, { code: 'SESSION_INVALID' })
      return res.json({ ok: true })
    }
  } catch (e) {
    console.error(e)
    return jsonError(res, 500, 'erro na sessao')
  }
})

app.post('/api/session/logout', async (req, res) => {
  const token = getBearerToken(req)
  if (!token) return jsonError(res, 401, 'missing bearer token')
  try {
    if (STORE_MODE === 'postgres') {
      await pool.query('update sessions set revoked_at = now() where token = $1 and revoked_at is null', [token])
    } else {
      await fileRevokeSessionToken(token)
    }
    return res.json({ ok: true })
  } catch (e) {
    console.error(e)
    return jsonError(res, 500, 'erro no logout')
  }
})

ensureSchema()
  .then(() => {
    app.listen(PORT, () => console.log(`PageWay (TreeBot accounts) listening on :${PORT} (mode=${STORE_MODE})`))
  })
  .catch((e) => {
    console.error('Failed to init schema', e)
    process.exit(1)
  })
