---
title: "⚙️ Customization"
---

Pass encoding options as the second constructor argument:

```ts
import { ExPass } from '@expass/node';

const secret = process.env['PASSWORD_SECRET'];
if (!secret) {
  throw new Error('PASSWORD_SECRET must be set');
}

const expass = new ExPass(secret, {
  power: 14,
  saltLength: 32,
});
```

## ⚙️ Encoding options

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

The Node.js scrypt implementation uses `r = 8` and `p = 2`. Increasing `power`
increases memory and CPU cost exponentially. Benchmark under expected concurrency
before changing it. The defaults describe the implementation, not a guarantee of
compliance with current password-storage guidance. Consult the
[OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt)
when choosing parameters.

## 🛡️ Verification limits

Encoding options are stored in the packed string. Verification reads those stored
options; setting `power` on a new instance does not replace the stored work factor.
The following constructor options restrict what `verify` will accept:

| Option | Accepted value |
| --- | --- |
| `allowPreHashAlgorithms` | Array of allowed hash algorithms |
| `allowPostHashAlgorithms` | Array of allowed hash algorithms |
| `allowHmacAlgorithms` | Array of allowed hash algorithms |
| `allowCipherAlgorithms` | Array of allowed cipher algorithms |
| `minSaltLength`, `maxSaltLength` | Salt length bounds in bytes |
| `minPower`, `maxPower` | Password scrypt cost exponent bounds |
| `minEncodeHashLength`, `maxEncodeHashLength` | Password scrypt output length bounds in bytes |
| `minKeyDerivationPower`, `maxKeyDerivationPower` | Encryption-key scrypt cost exponent bounds |

These limits are optional and unset by default. For example, an application that
only accepts passwords encoded with its current defaults could use:

```ts
import { ExPass } from '@expass/node';

const secret = process.env['PASSWORD_SECRET'];
if (!secret) {
  throw new Error('PASSWORD_SECRET must be set');
}

const verifier = new ExPass(secret, {
  allowPreHashAlgorithms: ['sha256'],
  allowPostHashAlgorithms: ['sha256'],
  allowHmacAlgorithms: ['sha256'],
  allowCipherAlgorithms: ['aes-256'],
  minPower: 14,
  maxPower: 14,
  minSaltLength: 16,
  maxSaltLength: 16,
  minEncodeHashLength: 64,
  maxEncodeHashLength: 64,
  minKeyDerivationPower: 10,
  maxKeyDerivationPower: 10,
});
```

Choose limits that also allow any older configurations you still need to verify.
A rejected parameter causes `verify` to throw. These limits apply during
verification, not during encoding.
