
import { HashAlgorithm } from '../../domain/interfaces';
import { Hasher as HasherInterface } from '../../domain/hasher';
import { fakeHash } from './fakehash';

export interface MockInterface {
    length: number,
    hash: jest.Mock<Buffer, [Buffer]>,
    hmac: jest.Mock<Buffer, [Buffer, Buffer]>,
    clear: () => void,
}

export const __mock: MockInterface = {
    length: 64,
    hash: jest.fn((data: Buffer) => fakeHash(data, __mock.length)),
    hmac: jest.fn((data: Buffer, key: Buffer) => fakeHash(Buffer.concat([data, key]), __mock.length)),
    clear: () => {
        __mock.hash.mockClear();
        __mock.hmac.mockClear();
    },
};

export class MockHasher<A extends HashAlgorithm> implements HasherInterface<A> {

    constructor(
        private readonly _algorithm: A
    ) {}

    get algorithm(): A {
        return this._algorithm;
    }

    hash(data: Buffer): Buffer {
        return __mock.hash(data);
    }

    hmac(data: Buffer, key: Buffer): Buffer {
        return __mock.hmac(data, key);
    }

}

