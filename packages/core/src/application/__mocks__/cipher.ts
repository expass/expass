
import { CipherAlgorithm } from '../../domain/interfaces';
import { Cipher } from '../../domain/cipher';

const fakeEncrypt = (data: Buffer, key: Buffer, iv: Buffer): Buffer => {
    return Buffer.from(data.toString('base64'), 'utf8');
};

const fakeDecrypt = (data: Buffer, key: Buffer, iv: Buffer): Buffer => {
    return Buffer.from(data.toString('utf8'), 'base64');
};

export interface MockInterface {
    length: number,
    encrypt: jest.Mock<Buffer, [Buffer, Buffer, Buffer]>,
    decrypt: jest.Mock<Buffer, [Buffer, Buffer, Buffer]>,
    clear: () => void,
}

export const __mock: MockInterface = {
    length: 64,
    encrypt: jest.fn((data: Buffer, key: Buffer, iv: Buffer) => fakeEncrypt(data, key, iv)),
    decrypt: jest.fn((data: Buffer, key: Buffer, iv: Buffer) => fakeDecrypt(data, key, iv)),
    clear: () => {
        __mock.encrypt.mockClear();
        __mock.decrypt.mockClear();
    },
};

export class MockCipher<A extends CipherAlgorithm> implements Cipher<A> {

    constructor(
        private readonly _algorithm: A
    ) {}

    get algorithm(): A {
        return this._algorithm;
    }

    encrypt(data: Buffer, key: Buffer, iv: Buffer): Buffer {
        return __mock.encrypt(data, key, iv);
    }

    decrypt(data: Buffer, key: Buffer, iv: Buffer): Buffer {
        return __mock.decrypt(data, key, iv);
    }

}
