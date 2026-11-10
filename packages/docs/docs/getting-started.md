---
title: "🚀 Getting Started"
---

ExPass provides `@expass/node` for Node.js applications and `@expass/core` for
implementing custom backends. The examples here use the Node.js implementation.

## 📥 Install

```bash
npm install @expass/node
```

## 🔑 Configure the pepper

Set `PASSWORD_SECRET` to a randomly generated secret supplied through your
application's secret management system. Keep it separate from the password database
and reuse it when verifying previously encoded passwords. Changing or losing the
secret prevents verification of those passwords; plan secret rotation explicitly.

On Linux or macOS, generate 32 random bytes and print them as Base64:

```bash
dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64
```

Run this once during initial setup and save the generated value in your secret
manager. Configure subsequent application runs with that same value rather than
generating a new secret at every startup. Pass the Base64 string directly to
ExPass; decoding it is not necessary.

## 🔐 Encode and verify

```ts
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

Store the entire returned string, including its `$expass$` prefix, options, salt,
and encrypted payload. Repeated calls to `encode` use fresh random salts.
The encryption applies to a derived hash, not the original password.

`verify` returns `false` for a password mismatch. Malformed encodings, unsupported
versions, rejected parameters, or other processing errors can throw; handle these
at your application's authentication boundary.

See [Customization](./customization.md) for options and verification limits, and
[Validation](./validation.md) for format checks.
