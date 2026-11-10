---
title: "✅ Validation"
---

`isExPassHash` checks whether a value can be unpacked as an ExPass string. It does
not verify a password, enforce verification limits, or guarantee that the encoded
parameters and version are supported. Use `verify` for authentication.

```ts
import { ExPass } from '@expass/node';

async function main() {
  const secret = process.env['PASSWORD_SECRET'];
  if (!secret) {
    throw new Error('PASSWORD_SECRET must be set');
  }

  const expass = new ExPass(secret);
  const encoded = await expass.encode('my_password');
  console.log(expass.isExPassHash(encoded)); // true
  console.log(expass.isExPassHash('not-an-expass-string')); // false
}

main().catch(console.error);
```

## ✅ Example with class-validator

Install `class-validator` in your application before using this optional
integration. A format check does not need your production pepper, so this validator
uses an instance with an empty secret exclusively for `isExPassHash`.

`expasshash.validator.ts`:

```ts
import { ValidatorConstraint } from 'class-validator';
import type { ValidatorConstraintInterface } from 'class-validator';
import { ExPass } from '@expass/node';

const formatChecker = new ExPass('');

@ValidatorConstraint({ name: 'expass', async: false })
export class IsExPassHashConstraint implements ValidatorConstraintInterface {
  validate(value: unknown): boolean {
    return typeof value === 'string' && formatChecker.isExPassHash(value);
  }

  defaultMessage(): string {
    return '$property must be a packed ExPass string';
  }
}
```

`import-user.dto.ts`:

```ts
import { Validate, IsString } from 'class-validator';
import { IsExPassHashConstraint } from './expasshash.validator';

export class ImportUserDto {
  @IsString()
  username!: string;

  @Validate(IsExPassHashConstraint)
  encodedPassword!: string;
}
```

This DTO is for importing already encoded values. A login or registration DTO
receives the user's plaintext password; authenticate with `verify` or encode it
with `encode` on the server instead of applying this format validator to it.
