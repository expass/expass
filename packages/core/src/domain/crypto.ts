
import { HashAlgorithm, CipherAlgorithm, KeyAndIv } from './interfaces';
import { Hasher } from './hasher';
import { Cipher } from './cipher';

export interface Crypto {
    createSalt(length: number): Buffer;
    createHasher<A extends HashAlgorithm>(algorithm: A): Hasher<A>;
    createCipher<A extends CipherAlgorithm>(algorithm: A): Cipher<A>;
    derivateKey(password: Buffer, salt: Buffer, algorithm: HashAlgorithm, iterations: number): Promise<KeyAndIv>;
    secureCompare(a: Buffer, b: Buffer): boolean;
}
