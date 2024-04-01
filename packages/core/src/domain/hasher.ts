
import { HashAlgorithm } from './interfaces';

export interface Hasher<A extends HashAlgorithm> {
    algorithm: A;
    hash: (data: Buffer) => Buffer;
    hmac: (data: Buffer, key: Buffer) => Buffer;
}
