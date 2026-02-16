# TreeBot Accounts (Railway)

Este diretório contém uma página + API simples para:
- criar contas (`POST /api/create`)
- validar login do app (`POST /api/login`)

## Deploy no Railway (resumo)

1. Crie um projeto no Railway e adicione um **Postgres**.
2. Faça deploy apontando o root para `Create_Accounts/`.
3. Configure as variáveis:
   - `DATABASE_URL` (Railway costuma fornecer automaticamente via Postgres)
   - (Opcional) `PGSSL=false` se seu Postgres não usar SSL (em Railway normalmente pode manter o padrão)
   - (Opcional) `ADMIN_KEY` (se definido, a criação de conta exige header `x-admin-key`)

## Usar no app

No TreeBot, crie um arquivo `treebot-config.json` ao lado do executável contendo:

```json
{ "authBaseUrl": "https://SEU-PROJETO.up.railway.app" }
```

## Endpoints

- `GET /health` → `{ ok: true }`
- `POST /api/create` body: `{ username, password }`
- `POST /api/login` body: `{ username, password }`

## Notas

- `username` é normalizado para minúsculo.
- senha é armazenada com hash `bcrypt`.
