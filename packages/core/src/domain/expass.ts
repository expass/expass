
import {
    ExPassConfig,
    ExPassConfigParams,
    HashAlgorithm,
    KeyAndIv,
} from './interfaces';

export interface ExPass {
    version: string;
    hash: (data: string | Buffer, algorithm: HashAlgorithm) => Buffer;
    hmac: (data: Buffer, key: Buffer, algorithm: HashAlgorithm) => Buffer;
    deriveSessionSalt: (salt: Buffer, preHash: Buffer, secret: Buffer, config: ExPassConfig) => Buffer;
    deriveCipherKeyIv: (secretSalt: Buffer, secret: Buffer, config: ExPassConfig) => Promise<{ key: Buffer, iv: Buffer }>;
    encrypt: (data: Buffer, keyAndIv: KeyAndIv, config: ExPassConfig) => Buffer;
    decrypt: (data: Buffer, keyAndIv: KeyAndIv, config: ExPassConfig) => Buffer;
    encode: (data: string, secret: Buffer, config: Partial<ExPassConfig>) => Promise<string>;
    verify: (data: string, hash: string, secret: Buffer, config: ExPassConfigParams) => Promise<boolean>;
    isExPassHash: (hash: string) => boolean;
}
