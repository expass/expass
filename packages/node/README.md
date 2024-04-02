# ExPass for node

Save your passwords securely with ExPass. ExPass is a library that allows you
to encrypt and compare passwords in a simple and secure way.

This library uses the scrypt algorithm to hash the password, and then follow the
official [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
recommendations to store the password.

> **Note:** This software is under revision and may have future changes.

## Features

* Use salt + pepper
* Use scrypt algorithm _(Against GPU/FPGA/ASIC attacks)_
* Add simetric encryption _(Against data breaches)_
* Use global secret (a.k.a. pepper) for extra security
* Customizable values
* Easy to use
* Modern and secure
* Use Promises

## Installation

```bash
npm install @expass/node 
```

## Usage

```JavaScript
import { ExPass } from '@expass/node';

const SECRET = 'UDxv1fCm4SQ9yMGN1h7cXxhseQ5B3b1J5FhJ26m4';

(async () => {
    const expass = new ExPass(SECRET);

    const encoded = await expass.encode('my_password');
    // $expass$v=1$fhuNdqUJe0hmYD7uGaAbmg$G2uVgUC0CnXoEy1lxs1BXuNd1sR9MDcP07b5.FxE1fGFMW7dDk_07eSEANZ.j5qX 

    const isValid = await expass.verify('my_password', encoded);
    // true

})();
```

## Customize params

```JavaScript
import { ExPass } from '@expass/node';

const SECRET = 'UDxv1fCm4SQ9yMGN1h7cXxhseQ5B3b1J5FhJ26m4';

(async () => {
    const expass = new ExPass(SECRET, {
        power: 20,
        saltLength: 32,
    });

    const encoded = await expass.encode('my_password');
})();
```

### Options

The options are:

| Option             | Type   | Description                                         | Default   |
| ------             | ----   | -----------                                         | -------   |
| power              | number | The power of the scrypt algorithm                   | 14        |
| encodeHashLenght   | number | The block size used to encode the password          | 64        |
| saltLength         | number | The length of the salt used in the scrypt algorithm | 16        |
| preHashAlgorithm   | string | The algorithm used to pre-hash the password         | 'sha256'  |
| postHashAlgorithm  | string | The algorithm used to post-hash the password        | 'sha256'  |
| hmacAlgorithm      | string | The algorithm used to generate the HMAC             | 'sha256'  |
| keyDerivationPower | number | The power of the scrypt for simetric key derivation | 10        |
| cipherAlgorithm    | string | The algorithm used to encrypt the password          | 'aes-256' |

## Contributing

If you want to contribute to this project, you can fork this repository and make
a pull request. You can also open an issue if you find a bug or have a
suggestion.

