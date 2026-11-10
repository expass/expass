# 🔐 ExPass for Node.js

Encode and verify passwords using scrypt, a random salt, and a shared pepper.
ExPass encrypts the derived hash before packing it for storage; it does not
provide recovery of the original password.

## ✨ Features

- Pre-hashing before password derivation.
- scrypt with a configurable work factor.
- A fresh random salt for each encoded password.
- A shared secret (pepper) supplied by the application.
- Symmetric encryption of the derived hash before storage.
- A packed string containing the version, salt, encoding options, and encrypted payload.
- Asynchronous password encoding and verification.
- Configurable algorithms and limits on parameters accepted during verification.

## 💡 Why?

I created ExPass because I needed a way to store passwords in a database using
password hashing, salts, and a separate application secret. The goal was to bring
those steps together behind a small API for encoding and verifying passwords.

scrypt provides the password derivation step through Node.js's built-in crypto
module. The pepper adds an application secret that can be kept separate from the
database, and the packed format keeps the information needed for verification
alongside each encoded password.

## 📥 Installation

```bash
npm install @expass/node
```

## 🚀 Usage

Set `PASSWORD_SECRET` to a randomly generated secret kept separately from your
password database. Use the same secret to verify existing passwords.

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

Store the complete encoded string. `verify` returns `false` for a password
mismatch; malformed encodings and other processing errors can throw.

## ⚙️ Options

Pass options as the second argument to `new ExPass(secret, options)`.

| Option | Type | Description | Default |
| --- | --- | --- | --- |
| `power` | number | scrypt cost exponent: `N = 2 ** power` | `14` |
| `encodeHashLength` | number | scrypt output length in bytes, before post-hashing | `64` |
| `saltLength` | number | Random salt length in bytes | `16` |
| `preHashAlgorithm` | string | Hash applied before scrypt | `'sha256'` |
| `postHashAlgorithm` | string | Hash applied to the scrypt output | `'sha256'` |
| `hmacAlgorithm` | string | HMAC used to derive the session salt | `'sha256'` |
| `keyDerivationPower` | number | scrypt cost exponent for deriving the encryption key and IV | `10` |
| `cipherAlgorithm` | string | AES-CBC variant used to encrypt the post-hash | `'aes-256'` |

Supported hash algorithms are `sha1`, `sha256`, and `sha512`. Prefer `sha256` or
`sha512` for new configurations. Supported cipher values are `aes-128` and
`aes-256`; the Node.js implementation uses CBC mode.

Benchmark work factors under your expected workload. See the
[customization guide](https://expass.js.org/docs/customization) for verification
limits, and consult current
[OWASP password-storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
when choosing parameters. The library's defaults do not establish compliance with
that guidance.

`isExPassHash` only checks whether a string can be unpacked. It does not verify a
password or enforce allowed parameters. See the
[validation guide](https://expass.js.org/docs/validation).

## 🤝 Contributing

Open an issue or pull request at [expass/expass](https://github.com/expass/expass).
