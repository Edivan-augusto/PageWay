const express = require('express')
const cors = require('cors')
const bcrypt = require('bcryptjs')
const path = require('node:path')
const fs = require('node:fs/promises')

const PORT = Number(process.env.PORT || 3000)
const DATABASE_URL = process.env.DATABASE_URL
const STORE_MODE = DATABASE_URL ? 'postgres' : 'file'

let pool = null
if (STORE_MODE === 'postgres') {
  // Só carrega pg quando for usar Postgres.
  const { Pool } = require('pg')
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: process.env.PGSSL === 'false' ? false : { rejectUnauthorized: false },
  })
}

function jsonError(res, status, message) {
  return res.status(status).json({ ok: false, error: message })
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
  // Railway normalmente permite escrever no filesystem do container, mas pode ser efêmero em redeploy.
  return path.join(process.cwd(), 'accounts.json')
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
}

const app = express()
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'OPTIONS'], allowedHeaders: ['Content-Type', 'x-admin-key'] }))
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
    return jsonError(res, 500, 'erro ao criar conta')
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
    return res.json({ ok: true })
  } catch (e) {
    console.error(e)
    return jsonError(res, 500, 'erro no login')
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

