---
title: Validation
---

You can validate a packed password by expass with the method `isExPassHash`:

```typescript
import { ExPass } from '@expass/node';

const expass = new ExPass('SECRET');

const hash = '...';

const valid = expass.isExPassHash(hash);
// true if is a valid pass hash

```

## Example with class-validator

Decorator:

```typescript
import { ValidatorConstraint, ValidatorConstraintInterface, ValidationArguments } from 'class-validator';
import { ExPass } from '@expass/node';

const expass = new Expass('');

@ValidatorConstraint({ name: 'expass', async: false }) // Set async to true for async validations
export class isExPassHash implements ValidatorConstraintInterface {
  validate(text: string, _args: ValidationArguments) {
    return expass.isExPassHash(text);
  }

  defaultMessage(_args: ValidationArguments) {
    return 'Text ($value) is not a valid ExPass hash!';
  }
}
```

user.dto:

```typescript
import { Validate, IsString } from 'class-validator';
import { isExPassHash } from './expasshash.decorator';

export class UserDto {

  @IsString()
  username: string;

  @Validate(isExPassHash)
  password: string;

}
```
