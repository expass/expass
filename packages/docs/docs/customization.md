---
title: Customization
---

You can customize some params for algorithms and options:

```typescript
import { ExPass } from '@expass/node';

const expass = new ExPass('SECRET', {
    power: 12,
    cipherAlgorithm: 'aes-128',
})

```

## Options

| Option             | Type   | Description                                         | Default   |
| ------             | ----   | -----------                                         | -------   |
| power              | number | The power of the scrypt algorithm                   | 14        |
| encodeHashLenght   | number | The block size used to encode the password          | 64        |
| saltLength         | number | The length of the salt used in the scrypt algorithm | 16        |
| preHashAlgorithm   | string | The algorithm used to pre-hash the password         | 'sha256'  |
| postHashAlgorithm  | string | The algorithm used to post-hash the password        | 'sha256'  |
| hmacAlgorithm      | string | The algorithm used to generate the HMAC             | 'sha256'  |
| keyDerivationPower | number | The power of the scrypt for symmetric key derivation | 10        |
| cipherAlgorithm    | string | The algorithm used to encrypt the password          | 'aes-256' |

### Available hash algorithms _(for this implementation)_

* sha1 _(not recommended)_
* sha256
* sha512

### Available cipher algorithms _(for this implementation)_

* aes-128
* aes-256

