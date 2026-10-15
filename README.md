# OAuth 2.0 Authorization Code com PKCE

Protótipo acadêmico em Python/FastAPI e PostgreSQL, executado integralmente com Docker. Implementa cliente público, scopes, PKCE S256, códigos de uso único, tokens opacos com hashes no banco, rotação de refresh token, login/consentimento e API protegida.

## 1. Pré-requisitos

- Docker Engine ou Docker Desktop
- Docker Compose v2
- Portas 8000 disponíveis

## 2. Preparação

Copie o ambiente e gere segredos:

```bash
cp .env.example .env
docker run --rm python:3.12-slim python -c "import secrets; print(secrets.token_urlsafe(48))"
docker run --rm python:3.12-slim sh -c "pip install -q cryptography && python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
```

Coloque o primeiro valor em APP_SECRET e TOKEN_PEPPER (gere valores separados) e o segundo em FERNET_KEY.

## 3. Construção e execução

```bash
docker compose build
docker compose up -d postgres api
docker compose --profile tools run --rm seed
docker compose ps
docker compose logs -f api
```

Acesse:

- Cadastro: http://localhost:8000/register
- Health: http://localhost:8000/health
- Documentação HTTP: http://localhost:8000/docs

Cadastre um usuário com senha de pelo menos 12 caracteres.

## 4. Postman - fluxo interativo

Em Authorization, selecione OAuth 2.0 e configure:

- Grant Type: Authorization Code (With PKCE)
- Callback URL: https://oauth.pstmn.io/v1/callback
- Auth URL: http://localhost:8000/oauth/authorize
- Access Token URL: http://localhost:8000/oauth/token
- Client ID: postman-public-client
- Client Secret: vazio
- Code Challenge Method: SHA-256
- Scope: profile:read offline_access
- Client Authentication: Send client credentials in body

Clique em Get New Access Token, faça login e use o token em GET http://localhost:8000/api/profile.

## 5. Newman no Docker

Os testes automatizados cobrem saúde, parâmetros ausentes, bearer ausente e bearer inválido:

```bash
docker compose --profile tests run --rm newman
```

O fluxo de login/consentimento é interativo e deve ser executado pela interface OAuth 2.0 do Postman. Os cenários negativos adicionais recomendados são: verifier incorreto, código reutilizado, código expirado, redirect divergente, scope não permitido, scope insuficiente, refresh reutilizado e ampliação de scope no refresh.

## 6. Inspeção do PostgreSQL

```bash
docker compose exec postgres psql -U oauth_user -d oauth_db
docker compose exec postgres psql -U oauth_user -d oauth_db -c "select event_type, success, created_at from audit_events order by id desc;"
```

## 7. Encerramento

```bash
docker compose down
docker compose down -v   # também apaga o banco
```

## Limites

Este é um protótipo acadêmico, não um servidor de identidade de produção. Não implementa OIDC/id_token, discovery, JWKS, MFA, federação, revocation/introspection, rate limiting distribuído, KMS/HSM, alta disponibilidade ou migrações Alembic.
