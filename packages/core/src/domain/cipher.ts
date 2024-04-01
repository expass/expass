
import { CipherAlgorithm } from './interfaces';

export interface Cipher<A extends CipherAlgorithm> {
    algorithm: A;
    encrypt: (data: Buffer, key: Buffer, iv: Buffer) => Buffer;
    decrypt: (data: Buffer, key: Buffer, iv: Buffer) => Buffer;
}
