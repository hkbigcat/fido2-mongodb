# FIDO2 / Passkeys Demo (Node.js + MongoDB)

A minimal, self-contained demo of **FIDO2 / WebAuthn** registration and authentication (passkeys) using:

- Node.js + Express
- MongoDB (Mongoose)
- [@simplewebauthn/server](https://github.com/MasterKale/SimpleWebAuthn) for secure server-side verification
- Vanilla browser WebAuthn API (`navigator.credentials.create` / `.get`) + small base64url helpers

No build step, no external browser bundle.

## Features

- Register a new user + passkey (or add additional passkey to existing user)
- Login with registered passkey
- View and delete registered credentials (for demo purposes)
- Session-based challenges (via express-session)
- Counter update on successful authentication (prevents replay)
- Clean Tailwind + Font Awesome UI

## Prerequisites

- Node.js (v18+ recommended)
- MongoDB server running locally (default `mongodb://127.0.0.1:27017`)
- Modern browser that supports WebAuthn (Chrome, Edge, Firefox, Safari)
- For full functionality: a platform authenticator (Windows Hello, Touch ID, Face ID, or a FIDO2 security key like YubiKey)

> The demo binds to `localhost` so it works without HTTPS during development. In production you **must** serve over HTTPS and update `RP_ID` / `ORIGIN`.

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. (Optional) Copy env and customize
cp .env.example .env
# Edit .env if you want a different Mongo URI, port, or RP settings

# 3. Make sure MongoDB is running
#    (mongod should already be active on port 27017)

# 4. Start the server
npm start
# or: node server.js

# 5. Open in browser
#    http://localhost:3000
```

## Usage

1. On the page, enter a username in the **Register** box and click **Register with Passkey**.
2. Your browser / OS will prompt you to create a passkey (fingerprint, PIN, security key, etc.).
3. After success you are automatically logged in and can see your registered credential(s).
4. Sign out, then use the **Login** box with the same username + **Login with Passkey** to authenticate.
5. While logged in you can register additional passkeys or remove existing ones.

## Project Structure

```
.
├── server.js           # Express app, API routes, Mongo models, SimpleWebAuthn logic
├── public/
│   └── index.html      # Self-contained demo UI + WebAuthn JS helpers
├── package.json
├── .env.example
└── README.md
```

## API Endpoints (for reference)

| Method | Path                        | Description |
|--------|-----------------------------|-------------|
| POST   | /api/register/options       | Returns `PublicKeyCredentialCreationOptions` |
| POST   | /api/register/verify        | Verifies attestation, stores credential |
| POST   | /api/login/options          | Returns `PublicKeyCredentialRequestOptions` |
| POST   | /api/login/verify           | Verifies assertion, logs user in |
| GET    | /api/me                     | Current session user |
| POST   | /api/logout                 | Destroy session |
| GET    | /api/credentials            | List current user's credentials |
| DELETE | /api/credentials/:id        | Remove a credential |

All registration/login flows use short-lived challenges stored in the user's session.

## Configuration (RP settings)

WebAuthn is very strict about the **Relying Party ID** and **origin**.

- `RP_ID` must be a valid domain suffix of your site (e.g. `localhost` or `example.com`)
- `ORIGIN` must exactly match the protocol + host + port the page is served from

Change via environment variables (see `.env.example`).

## Notes & Limitations (Demo)

- Uses `attestationType: 'none'` (most common for passkeys).
- `userVerification: 'preferred'` (allows both UV and non-UV authenticators).
- `residentKey: 'preferred'` (allows discoverable credentials when the authenticator supports it).
- Login still requires the username (common pattern). True "username-less" would use `allowCredentials: []` + resident keys + more UI work.
- No rate limiting, no production hardening (this is a learning demo).
- Sessions are in-memory (restart = logged out). Easy to switch to connect-mongo if desired.
- Only one MongoDB collection (`users`).

## Troubleshooting

- **"NotAllowedError" or prompt doesn't appear**: Make sure you're on `localhost` (or HTTPS). Some browsers block WebAuthn on plain HTTP except localhost.
- **User already exists but can't login**: The user must have at least one credential.
- **Verification fails with "No pending challenge"**: The verify call must be made in the same browser session (cookie) that received the options.
- **Mongo connection errors**: Confirm `mongod` is running and listening on 27017.
- **Old users break**: The DB schema evolved during development; you can drop the collection or delete users without a valid `userID`.

## Useful Resources

- [WebAuthn.io](https://webauthn.io) – excellent visual playground
- [SimpleWebAuthn docs](https://simplewebauthn.dev)
- [MDN Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)
- [FIDO Alliance](https://fidoalliance.org)

---

Enjoy experimenting with passwordless auth!
