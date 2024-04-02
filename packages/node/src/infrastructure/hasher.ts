
import { createHash, createHmac } from 'crypto';
import { HasherInterface, interfaces } from '@expass/core';

type HashAlgorithm = interfaces.HashAlgorithm;

export class NodeHasher<A extends HashAlgorithm> implements HasherInterface<A> {

    constructor(
        protected readonly _algorithm: A,
    ) {}

    get algorithm(): A {
        return this._algorithm;
    }

    hash(data: Buffer): Buffer {
        return createHash(this.algorithm).update(data).digest();
    }

    hmac(data: Buffer, key: Buffer): Buffer {
        return createHmac(this.algorithm, key).update(data).digest();
    }

}
