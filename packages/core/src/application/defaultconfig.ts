
import { ExPassConfig } from '../domain/interfaces';

export const DefaultConfig: ExPassConfig = {
    preHashAlgorithm: 'sha256',
    postHashAlgorithm: 'sha256',
    hmacAlgorithm: 'sha256',
    saltLength: 16,
    power: 14,
    encodeHashLenght: 64,
    keyDerivationPower: 10,
    cipherAlgorithm: 'aes-256'
};
