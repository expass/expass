
import { ExPassError as ExPassErrorInterface } from '../domain/errors';

export class ExPassVersionMismatchError extends Error implements ExPassErrorInterface {
  constructor(message: string = 'Version mismatch') {
    super(message);
    this.name = 'ExPassVersionMismatchError';
  }
}

export class ExPassInvalidHashError extends Error implements ExPassErrorInterface {
  constructor(message: string = 'Invalid hash format') {
    super(message);
    this.name = 'ExPassrInvalidHashError';
  }
}

export class ExPassForbidenParamValueError extends Error implements ExPassErrorInterface {
  constructor(message: string = 'Forbiden parameter value') {
    super(message);
    this.name = 'ExPassForbidenParamValueError';
  }
}
