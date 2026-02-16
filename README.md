# TreeBot Accounts (Railway)

Este diretório contém uma página + API simples para:
- criar contas (`POST /api/create`)
- validar login do app (`POST /api/login`)

## Deploy no Railway (resumo)

1. Crie um projeto no Railway.
2. Faça deploy apontando o root para `Create_Accounts/`.
3. (Opcional) Configure variáveis:
   - `ADMIN_KEY` (se definido, a criação de conta exige header `x-admin-key`)
   - `ACCOUNTS_FILE` (caminho do arquivo `accounts.json` se quiser customizar)

> Sem Postgres: por padrão o servidor salva em `accounts.json` no filesystem do container. Em Railway isso pode ser
> **efêmero** (pode resetar em redeploy/restart). Se você quiser persistência real, use Postgres ou outro storage.

## Usar no app

O TreeBot valida login via `POST /api/login` no servidor que você publicar no Railway.

## Endpoints

- `GET /health` → `{ ok: true }`
- `POST /api/create` body: `{ username, password }`
- `POST /api/login` body: `{ username, password }`

## Notas

- `username` é normalizado para minúsculo.
- senha é armazenada com hash `bcrypt`.
