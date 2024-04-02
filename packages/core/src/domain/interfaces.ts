
export type HashAlgorithm = 'sha1' | 'sha256' | 'sha512';

export type CipherAlgorithm = 'aes-128' | 'aes-256';

export interface ExPassConfig {
    preHashAlgorithm: HashAlgorithm;
    postHashAlgorithm: HashAlgorithm;
    hmacAlgorithm: HashAlgorithm;
    saltLength: number;
    power: number;
    encodeHashLenght: number;
    keyDerivationPower: number;
    cipherAlgorithm: CipherAlgorithm;
}

export interface ExPassConfigParams extends Partial<ExPassConfig> {
    allowPreHashAlgorithms?: HashAlgorithm[] | null;
    allowPostHashAlgorithms?: HashAlgorithm[] | null;
    allowCipherAlgorithms?: CipherAlgorithm[] | null;
    allowHmacAlgorithms?: HashAlgorithm[] | null;
    minSaltLength?: number | null;
    maxSaltLength?: number | null;
    minPower?: number | null;
    maxPower?: number | null;
    minEncodeHashLength?: number | null;
    maxEncodeHashLength?: number | null;
    minKeyDerivationPower?: number | null;
    maxKeyDerivationPower?: number | null;
}

export interface VersionedExPassConfig extends ExPassConfig {
    version: string;
}

export type ConfigFlag = keyof ExPassConfig;

export type ConfigFlagRef<K extends ConfigFlag> = K;

export type ConfigFlagTypeRef<K extends ConfigFlag> = ExPassConfig[K];

export interface ResumedExPassConfig {
    v: string,
    pra?: ConfigFlagTypeRef<'preHashAlgorithm'>;
    poa?: ConfigFlagTypeRef<'postHashAlgorithm'>;
    h?: ConfigFlagTypeRef<'hmacAlgorithm'>;
    sl?:  ConfigFlagTypeRef<'saltLength'>;
    p?:   ConfigFlagTypeRef<'power'>;
    el?: ConfigFlagTypeRef<'encodeHashLenght'>;
    kp?: ConfigFlagTypeRef<'keyDerivationPower'>;
    ca?:  ConfigFlagTypeRef<'cipherAlgorithm'>;
}

export type ResumedExPassConfigFlag = keyof ResumedExPassConfig;

export type ResumedExPassConfigFlagRef<K extends ResumedExPassConfigFlag> = K;

export interface ExPassPackage {
    version: string;
    salt: Buffer;
    body: Buffer;
    config: ExPassConfig;
}

export interface KeyAndIv {
    key: Buffer;
    iv: Buffer;
}
