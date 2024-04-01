
export type HashAlgorithm = 'sha1' | 'sha256' | 'sha512';

export type CipherAlgorithm = 'aes-128' | 'aes-256';

export interface ExPassConfig {
    preHashAlgorithm: HashAlgorithm;
    postHashAlgorithm: HashAlgorithm;
    saltLength: number;
    power: number;
    keyDerivationAlgorithm: HashAlgorithm;
    keyDerivationIterations: number;
    cipherAlgorithm: CipherAlgorithm;
}

export interface ExPassConfigParams extends Partial<ExPassConfig> {
    allowPreHashAlgorithms?: HashAlgorithm[] | null;
    allowPostHashAlgorithms?: HashAlgorithm[] | null;
    allowKeyDerivationAlgorithms?: HashAlgorithm[] | null;
    allowCipherAlgorithms?: CipherAlgorithm[] | null;
    minSaltLength?: number | null;
    maxSaltLength?: number | null;
    minPower?: number | null;
    maxPower?: number | null;
    minKeyDerivationIterations?: number | null;
    maxKeyDerivationIterations?: number | null;
}

export type ConfigFlag = keyof ExPassConfig;

export type ConfigFlagRef<K extends ConfigFlag> = K;

export type ConfigFlagTypeRef<K extends ConfigFlag> = ExPassConfig[K];

export interface ResumedExPassConfig {
    pra?: ConfigFlagTypeRef<'preHashAlgorithm'>;
    poa?: ConfigFlagTypeRef<'postHashAlgorithm'>;
    sl?:  ConfigFlagTypeRef<'saltLength'>;
    p?:   ConfigFlagTypeRef<'power'>;
    kda?: ConfigFlagTypeRef<'keyDerivationAlgorithm'>;
    kdi?: ConfigFlagTypeRef<'keyDerivationIterations'>;
    ca?:  ConfigFlagTypeRef<'cipherAlgorithm'>;
}

export type ResumedExPassConfigFlag = keyof ResumedExPassConfig;

export type ResumedExPassConfigFlagRef<K extends ResumedExPassConfigFlag> = K;

export interface ExPassPackage {
    salt: Buffer;
    body: Buffer;
    config: ExPassConfig;
}

export interface KeyAndIv {
    key: Buffer;
    iv: Buffer;
}
