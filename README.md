# Auth Server (OpenID Provider) — Opção 1

Servidor de Autorização OAuth 2.0 + OpenID Connect (Authorization Code + PKCE S256), ID Token RS256.
Spring Boot 3.5 / Java 21. Roda em **https://localhost:9000**.

## Executar
1. Copie `.env.example` para `.env` e preencha (o `.env` é ignorado pelo git).
2. Gere o certificado TLS de desenvolvimento:
   `AUTH_KEYSTORE_PASSWORD=<mesma do .env> ./scripts/gen-certs.sh` (Windows: `scripts\gen-certs.cmd`)
3. `./mvnw spring-boot:run`
4. Teste: `curl -k https://localhost:9000/.well-known/openid-configuration`

## Endpoints (tabela da seção 2 do enunciado)
`/.well-known/openid-configuration` · `/authorize` (GET/POST) · `/token` · `/userinfo` (GET/POST) · `/jwks.json` · `/logout` (POST)
Extras: `/register` (cadastro de usuários) e `GET /logout` (página que submete o POST com CSRF e volta para a aplicação).
Coleção de requisições: `docs/auth-server.postman_collection.json`.

## Usuários e cadastro
- Os usuários ficam em um banco **H2 em arquivo** (`data/authdb`, senha em `AUTH_DB_PASSWORD`, fora do git), tabela `users` (`schema.sql`).
- **Cadastro:** `https://localhost:9000/register`. A senha é criada e guardada **só aqui** (bcrypt custo 12); a aplicação nunca a vê.
  Validações: usuário `[a-z0-9._-]{3,32}`, e-mail, senha de 10 a 72 bytes, confirmação; limite de 5 cadastros/hora por IP; CSRF ativo.
- `sub` = UUID aleatório gerado no cadastro (estável e nunca reatribuído).
- **Role:** todo cadastro nasce como `adotante` e com `email_verified=false` (não há confirmação por e-mail neste trabalho, então o claim é honesto).
  O token leva a role como claim `role`; a aplicação usa esse claim (validado) para autorização.
- **Promover alguém a admin:** liste o username em `OIDC_BOOTSTRAP_ADMINS` no `.env` e reinicie.
- Usuários de teste criados no startup (se não existirem): `admin` (role `admin`) e `operador` (role `user`); senhas em `SEED_ADMIN_PASSWORD` / `SEED_USER_PASSWORD`.

## Decisões de segurança
- Sem segredos no repositório: `client_secret`, senhas do seed, do banco e do keystore vêm de variáveis de ambiente/`.env`.
- TLS obrigatório; cookie de sessão `HttpOnly; Secure; SameSite=Lax`, id rotacionado no login.
- Senhas com bcrypt (custo 12); rate limiting por IP+usuário (5/5 min) e por IP (20/5 min); mensagem genérica; hash "fantasma" para uniformizar o tempo (sem enumeração por tempo).
- `redirect_uri` por comparação exata; client/redirect inválidos nunca geram redirect (erros de parâmetros voltam ao cliente já validado, com `state`).
- Authorization code: 256 bits, uso único (atômico), 60 s, vinculado a client/redirect/challenge/sub/nonce; reuso revoga os tokens.
- ID Token RS256 com `kid`; chave privada em `data/signing-key.json` (fora do git); rotação automática mantendo a chave anterior no JWKS.
- ID Token com TTL de 900 s: curto o bastante para limitar o dano de um vazamento e suficiente para o login; a sessão local tem ciclo próprio.
- Access token opaco (não é JWT). Sem refresh token: o enunciado define `authorization_code` como único grant (`unsupported_grant_type` para os demais).
- Erros padronizados (2.8): `invalid_request`, `invalid_client` (401 + `WWW-Authenticate`), `invalid_grant`, `unauthorized_client`, `unsupported_grant_type`, `invalid_scope`.
- CSRF ativo no login, no cadastro e no `/logout`; `/token` e `/userinfo` isentos (autenticados por segredo/Bearer).
- `post_logout_redirect_uri` só é aceito se idêntico ao valor cadastrado (sem open redirect).
