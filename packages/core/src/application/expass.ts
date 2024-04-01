
import 'reflect-metadata';
import { injectable, inject } from 'tsyringe';
import { DefaultConfig } from './defaultconfig';
import { 
    ExPassConfig,
    ExPassConfigParams,
    HashAlgorithm,
    CipherAlgorithm,
    KeyAndIv,
} from '../domain/interfaces';
import { ExPass as ExPassInterface } from '../domain/expass';
import { Encoder } from '../domain/encoder';
import { Packager } from '../domain/packager';
import { Crypto } from '../domain/crypto';
import { Hasher } from '../domain/hasher';
import { Cipher } from '../domain/cipher';

@injectable()
export class ExPass implements ExPassInterface {

    constructor(
        @inject('Packager') protected packager: Packager,
        @inject('Crypto') protected crypto: Crypto,
        @inject('Encoder') protected encoder: Encoder,
    ) {}

    hash(data: string | Buffer, algorithm: HashAlgorithm): Buffer {
        if (typeof data === 'string') {
            data = Buffer.from(data, 'utf8');
        }
        const hasher = this.crypto.createHasher(algorithm);
        return hasher.hash(data);
    }

    hmac(data: Buffer, key: Buffer, algorithm: HashAlgorithm): Buffer {
        const hasher = this.crypto.createHasher(algorithm);
        return hasher.hmac(data, key);
    }

    derivateSessionSalt(salt: Buffer ,preHash: Buffer, secret: Buffer, config: ExPassConfig): Buffer {
        const hasher = this.crypto.createHasher(config.keyDerivationAlgorithm);
        let secretSalt: Buffer = Buffer.alloc(0);
        // Add buffers until the salt was larger or equal to config
        while (secretSalt.length < config.saltLength) {
            const toHash = Buffer.concat([
                secretSalt,
                salt
            ]);

            secretSalt = Buffer.concat([
                hasher.hmac(hasher.hmac(salt, preHash), secret),
                secretSalt
            ]);
        }

        // Cut result to have salt length
        return secretSalt.slice(0, config.saltLength);
    }

    async derivateCipherKeyIv(secretSalt: Buffer, secret: Buffer, config: ExPassConfig): Promise<KeyAndIv> {
        return this.crypto.derivateKey(
            secretSalt,
            secret,
            config.keyDerivationAlgorithm,
            config.keyDerivationIterations,
        );
    }

    encrypt(data: Buffer, keyIv: KeyAndIv, config: ExPassConfig): Buffer {
        const cipher = this.crypto.createCipher(config.cipherAlgorithm);
        return cipher.encrypt(data, keyIv.key, keyIv.iv);
    }

    decrypt(data: Buffer, keyIv: KeyAndIv, config: ExPassConfig): Buffer {
        const cipher = this.crypto.createCipher(config.cipherAlgorithm);
        return cipher.decrypt(data, keyIv.key, keyIv.iv);
    }

    async generateHashedPassword(preHash: Buffer, secretSalt: Buffer, config: ExPassConfig): Promise<Buffer> {
        const postHasher = this.crypto.createHasher(config.postHashAlgorithm);
        const encoded = await this.encoder.encode(
            preHash,
            secretSalt,
            config.power,
            config.encodeBlockSize,
        );

        return postHasher.hash(encoded);
    }

    async encode(clearPassword: string, secret: Buffer, config: Partial<ExPassConfig> ): Promise<string> {
        const finalConfig: ExPassConfig = {
            ...DefaultConfig,
            ...config,
        };

        // Pre-salt password
        const preHash = this.crypto.createHasher(finalConfig.preHashAlgorithm)
            .hash(Buffer.from(clearPassword, 'utf8'));

        // Generate random salt
        const salt = this.crypto.createSalt(finalConfig.saltLength);

        // Derivate secretSalt
        const secretSalt = this.derivateSessionSalt(
            salt,
            preHash,
            secret,
            finalConfig,
        );

        // Encode password
        const encodedPassword = await this.generateHashedPassword(
            preHash,
            secretSalt,
            finalConfig,
        );

        // Derivate cipher key and iv
        const keyAndIv = await this.derivateCipherKeyIv(
            secretSalt,
            secret,
            finalConfig,
        );

        // Encrypt result
        const cipheredPayload = this.encrypt(
            encodedPassword, 
            keyAndIv,
            finalConfig,
        );
        
        return this.packager.pack(salt, cipheredPayload, finalConfig);
    }

    async compare(clearPassword: string, hash: string, secret: Buffer, config: ExPassConfigParams): Promise<boolean> {
        const {
            body: cipheredPayload,
            salt,
            config: finalConfig} = this.packager.unpack(hash);

        const {
            preHashAlgorithm,
            postHashAlgorithm,
            saltLength,
            power,
            encodeBlockSize,
            keyDerivationAlgorithm,
            keyDerivationIterations,
            cipherAlgorithm,
        } = finalConfig;

        if (config.allowPreHashAlgorithms && !config.allowPreHashAlgorithms.includes(preHashAlgorithm)) {
            throw new Error(`Not allowed preHashAlgorithm: ${preHashAlgorithm}`);
        } 

        if (config.allowPostHashAlgorithms && !config.allowPostHashAlgorithms.includes(postHashAlgorithm)) {
            throw new Error(`Not allowed postHashAlgorithm: ${postHashAlgorithm}`);
        }

        if (config.allowKeyDerivationAlgorithms && !config.allowKeyDerivationAlgorithms.includes(keyDerivationAlgorithm)) {
            throw new Error(`Not allowed keyDerivationAlgorithm: ${keyDerivationAlgorithm}`);
        }

        if (config.allowCipherAlgorithms && !config.allowCipherAlgorithms.includes(cipherAlgorithm)) {
            throw new Error(`Not allowed cipherAlgorithm: ${cipherAlgorithm}`);
        }

        if (config.minSaltLength && saltLength < config.minSaltLength) {
            throw new Error(`Salt length is too short: ${saltLength}`);
        }

        if (config.maxSaltLength && saltLength > config.maxSaltLength) {
            throw new Error(`Salt length is too long: ${saltLength}`);
        }

        if (config.minPower && power < config.minPower) {
            throw new Error(`Power is too low: ${power}`);
        }

        if (config.maxPower && power > config.maxPower) {
            throw new Error(`Power is too high: ${power}`);
        }

        if (config.minEncodeBlockSize && encodeBlockSize < config.minEncodeBlockSize) {
            throw new Error(`Encode block size is too low: ${encodeBlockSize}`);
        }

        if (config.maxEncodeBlockSize && encodeBlockSize > config.maxEncodeBlockSize) {
            throw new Error(`Encode block size is too high: ${encodeBlockSize}`);
        }

        if (config.minKeyDerivationIterations && keyDerivationIterations < config.minKeyDerivationIterations) {
            throw new Error(`Key derivation iterations is too low: ${keyDerivationIterations}`);
        }

        if (config.maxKeyDerivationIterations && keyDerivationIterations > config.maxKeyDerivationIterations) {
            throw new Error(`Key derivation iterations is too high: ${keyDerivationIterations}`);
        }

        if (salt.length !== saltLength) {
            throw new Error(`Salt length mismatch: ${salt.length} !== ${saltLength}`);
        }

        // Pre-salt password
        const preHash = this.crypto.createHasher(finalConfig.preHashAlgorithm)
            .hash(Buffer.from(clearPassword, 'utf8'));

        // Derivate secretSalt
        const secretSalt = this.derivateSessionSalt(
            salt,
            preHash,
            secret,
            finalConfig,
        );

        // Derivate cipher key and iv
        const keyAndIv = await this.derivateCipherKeyIv(
            secretSalt,
            secret,
            finalConfig,
        );

        // Decrypt saved hash
        const encodedSavedPassword = this.decrypt(
            cipheredPayload, 
            keyAndIv,
            finalConfig,
        );

        // Encode password
        const encodedPassword = await this.generateHashedPassword(
            preHash,
            secretSalt,
            finalConfig,
        );

        return this.crypto.secureCompare(encodedPassword, encodedSavedPassword);
    }

}

