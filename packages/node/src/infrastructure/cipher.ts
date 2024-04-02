
import { createCipheriv, createDecipheriv } from 'crypto';
import { CipherInterface, interfaces } from '@expass/core';

type CipherAlgorithm = interfaces.CipherAlgorithm;

export class NodeCipher<A extends CipherAlgorithm> implements CipherInterface<A> {

    constructor(
        protected readonly _algorithm: A,
    ) {}

    get algorithm(): A {
        return this._algorithm;
    }

    get cbcAlgorithm(): string {
        return `${this.algorithm}-cbc`;
    }

    encrypt(data: Buffer, key: Buffer, iv: Buffer): Buffer {
        const cipher = createCipheriv(this.cbcAlgorithm, key, iv);
        return Buffer.concat([cipher.update(data), cipher.final()]);
    }

    decrypt(data: Buffer, key: Buffer, iv: Buffer): Buffer {
        const cipher = createDecipheriv(this.cbcAlgorithm, key, iv);
        return Buffer.concat([cipher.update(data), cipher.final()]);
    }

}
