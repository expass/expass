# 🔐 ExPass

Password encoding for Node.js using scrypt, a random salt, and a shared pepper.
The derived hash is encrypted and packed into a string for storage; the original
password is not encrypted for later recovery.

## ✨ Features

- Pre-hashing before password derivation.
- scrypt with a configurable work factor.
- A fresh random salt for each encoded password.
- A shared secret (pepper) supplied by the application.
- Symmetric encryption of the derived hash before storage.
- A packed string containing the version, salt, encoding options, and encrypted payload.
- Asynchronous password encoding and verification.
- Replaceable cryptographic components and custom backends through `@expass/core`.

## 💡 Why?

I created ExPass because I needed a way to store passwords in a database using
password hashing, salts, and a separate application secret. The goal was to bring
those steps together behind a small API for encoding and verifying passwords.

scrypt provides the password derivation step through Node.js's built-in crypto
module. The pepper adds an application secret that can be kept separate from the
database, and the packed format keeps the information needed for verification
alongside each encoded password.

## ⚖️ How ExPass compares

This table compares the Node.js implementation of ExPass with the `bcrypt` and
`argon2` npm packages and Node.js's built-in `crypto.scrypt` API. It describes what
each API provides out of the box; applications can add their own processing around
these APIs.

| Feature | ExPass (`@expass/node`) | `bcrypt` | `argon2` | Node.js `crypto.scrypt` |
| --- | --- | --- | --- | --- |
| Password derivation | scrypt | bcrypt | Argon2id by default | scrypt |
| Salt handling | Generated automatically | Generated when a numeric cost is passed to `hash` | Generated automatically unless supplied | Application supplies the salt |
| Pepper integration | Required constructor secret | Application implements it | Optional `secret` parameter | Application implements it |
| Separate pre-hash step | Included | Application implements it if needed | Application implements it if needed | Application implements it if needed |
| Encryption of the derived hash | Included (AES-CBC) | Application implements it if needed | Application implements it if needed | Application implements it if needed |
| Stored result | ExPass string with version, options, salt, and encrypted payload | bcrypt string with version, cost, salt, and hash | Encoded string with algorithm, version, parameters, salt, and hash | Derived bytes; application chooses the storage format |
| Cost controls | Password and encryption-key scrypt cost exponents | bcrypt cost factor | Memory, time, and parallelism | `N`, `r`, and `p` |

ExPass combines password derivation, pepper handling, encryption, and packaging
behind `encode` and `verify`. Using `crypto.scrypt` directly gives the application
control over how those steps are assembled. The `bcrypt` and `argon2` packages
also provide hashing and verification APIs with encoded storage formats.

### 🛡️ Additional protection beyond password hashing

ExPass combines scrypt with an application-held pepper and encryption of the
derived hash. Unlike a basic bcrypt setup without a pepper, a stolen database
alone does not contain everything needed to verify password guesses: the attacker
also needs the application's secret, provided it remains confidential and separate
from the database.

These protections are built into ExPass, so applications can use them through a
single encoding and verification API. Other implementations can also incorporate
a pepper; ExPass provides this combination out of the box.

Sources: [bcrypt API](https://github.com/kelektiv/node.bcrypt.js#usage),
[node-argon2 usage](https://github.com/ranisalt/node-argon2#usage) and
[secret parameter implementation](https://github.com/ranisalt/node-argon2/blob/master/argon2.cjs),
and [Node.js scrypt API](https://nodejs.org/api/crypto.html#cryptoscryptpassword-salt-keylen-options-callback).

## 📦 Packages

- [`@expass/node`](https://www.npmjs.com/package/@expass/node): the Node.js implementation.
- `@expass/core`: interfaces and building blocks for custom implementations.

## 📥 Installation

```bash
npm install @expass/node
```

## 🚀 Usage

Set `PASSWORD_SECRET` to a randomly generated secret stored separately from your
password database. Keep it available for future verification.

```javascript
import { ExPass } from '@expass/node';

async function main() {
  const secret = process.env['PASSWORD_SECRET'];
  if (!secret) {
    throw new Error('PASSWORD_SECRET must be set');
  }

  const expass = new ExPass(secret);
  const encoded = await expass.encode('my_password');

  // Store encoded in the database, then verify at login:
  const isValid = await expass.verify('my_password', encoded);
  console.log(isValid); // true
}

main().catch(console.error);
```

A password mismatch returns `false`; malformed encodings and other processing
errors can throw. Handle those errors at your authentication boundary.

## ⚙️ Customization

The second constructor argument accepts encoding options and verification limits.
For example, `new ExPass(secret, { power: 14, saltLength: 32 })` changes the random
salt length. `power` is a scrypt exponent (`N = 2 ** power`), so increasing it raises
CPU and memory costs exponentially.

See the [full documentation](https://expass.js.org/docs/intro), including
[options and verification limits](packages/docs/docs/customization.md),
[format validation](packages/docs/docs/validation.md), and the
[encoding flow](packages/docs/docs/intro.md#encoding-flow).

## 🛠️ Development

Use Node.js 24 and install dependencies with `npm ci`.
Run `npm run typecheck` to check library and test types, `npm test` to run tests,
and `npm run build` to build the packages and documentation.

Builds and type checks use native TypeScript 7 via the `@typescript/native` npm
alias (`tsc`). The `typescript` alias provides the TypeScript 6 compatibility API
required by `ts-jest` and `ts-node`; `tsc6` is available for comparison.
Keep both aliases when updating the compiler until those tools support the native API.

## 🔒 Password-storage guidance

scrypt is available through Node.js's built-in crypto module. Its memory cost
helps make password guessing more expensive. Select parameters based on your
application's workload and current
[OWASP guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
The library's defaults are implementation defaults, not a claim of compliance.

The pepper must remain separate from the database. Changing or losing it prevents
verification of existing encoded passwords; plan rotation explicitly.
