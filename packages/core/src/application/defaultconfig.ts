
import { ExPassConfig } from '../domain/interfaces';

export const DefaultConfig: ExPassConfig = {
    preHashAlgorithm: 'sha256',
    postHashAlgorithm: 'sha256',
    saltLength: 16,
    power: 8,
    encodeBlockSize: 64,
    keyDerivationAlgorithm: 'sha256',
    keyDerivationIterations: 10000,
    cipherAlgorithm: 'aes-256'
};
