
import { HashAlgorithm, CipherAlgorithm, KeyAndIv } from '../../domain/interfaces';
import { Crypto } from '../../domain/crypto';
import { Hasher } from '../../domain/hasher';
import { Cipher } from '../../domain/cipher';
import { MockHasher } from './hasher';
import { MockCipher } from './cipher';
import { fakeHash } from './fakehash';

interface MockInterface {
    createSalt: jest.Mock<Buffer, [number]>,
    createHasher: jest.Mock<Hasher<HashAlgorithm>, [HashAlgorithm]>,
    createCipher: jest.Mock<Cipher<CipherAlgorithm>, [CipherAlgorithm]>,
    deriveKey: jest.Mock<Promise<KeyAndIv>, [Buffer, Buffer, CipherAlgorithm, number]>,
    secureCompare: jest.Mock<boolean, [Buffer, Buffer]>,
    clear: () => void,
}

export const __mock: MockInterface = {
    createSalt: jest.fn((length: number) => Buffer.alloc(length)),
    createHasher: jest.fn((algorithm: HashAlgorithm) => new MockHasher(algorithm)),
    createCipher: jest.fn((algorithm: CipherAlgorithm) => new MockCipher(algorithm)),
    deriveKey: jest.fn((password: Buffer, salt: Buffer, algorithm: CipherAlgorithm, power: number) => {
        return Promise.resolve({
            key: fakeHash(Buffer.concat([password, salt]), 32),
            iv: fakeHash(Buffer.concat([salt, password]), 16),
        });
    }),
    secureCompare: jest.fn((a: Buffer, b: Buffer) => a.equals(b)),
    clear: () => {
        __mock.createSalt.mockClear();
        __mock.createHasher.mockClear();
        __mock.createCipher.mockClear();
        __mock.deriveKey.mockClear();
        __mock.secureCompare.mockClear();
    },
};

export class MockCrypto implements Crypto {

    createSalt(length: number): Buffer {
        return __mock.createSalt(length);
    }

    createHasher<A extends HashAlgorithm>(algorithm: A): Hasher<A> {
        return __mock.createHasher(algorithm) as Hasher<A>;
    }

    createCipher<A extends CipherAlgorithm>(algorithm: A): Cipher<A> {
        return __mock.createCipher(algorithm) as Cipher<A>;
    }

    deriveKey(password: Buffer, salt: Buffer, algorithm: CipherAlgorithm, power: number): Promise<KeyAndIv> {
        return __mock.deriveKey(password, salt, algorithm, power);
    }

    secureCompare(a: Buffer, b: Buffer): boolean {
        return __mock.secureCompare(a, b);
    }

}
