
import 'reflect-metadata';
import { injectable, inject, singleton } from 'tsyringe';
import { DefaultConfig } from './defaultconfig';
import { 
    ExPassConfig,
    ExPassConfigParams,
    HashAlgorithm,
    CipherAlgorithm,
    KeyAndIv,
} from '../domain/interfaces';
import { ExPassVersionMismatchError, ExPassForbidenParamValueError } from './errors';
import { ExPass as ExPassInterface } from '../domain/expass';
import { Encoder } from '../domain/encoder';
import { Packager } from '../domain/packager';
import { Crypto } from '../domain/crypto';
import { Hasher } from '../domain/hasher';
import { Cipher } from '../domain/cipher';

@injectable()
@singleton()
export class ExPass implements ExPassInterface {

    private _version: string = '1';

    constructor(
        @inject('Packager') protected packager: Packager,
        @inject('Crypto') protected crypto: Crypto,
        @inject('Encoder') protected encoder: Encoder,
    ) {}

    get version(): string {
        return this._version;
    }

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
        const hasher = this.crypto.createHasher(config.hmacAlgorithm);
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
            config.cipherAlgorithm,
            config.keyDerivationPower
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
            config.encodeHashLenght,
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
        
        return this.packager.pack(salt, cipheredPayload, {
            version: this.version,
            ...finalConfig
        });
    }

    async compare(clearPassword: string, hash: string, secret: Buffer, config: ExPassConfigParams): Promise<boolean> {
        const {
            version,
            body: cipheredPayload,
            salt,
            config: finalConfig} = this.packager.unpack(hash);

        const {
            preHashAlgorithm,
            postHashAlgorithm,
            hmacAlgorithm,
            saltLength,
            power,
            encodeHashLenght,
            keyDerivationPower,
            cipherAlgorithm,
        } = finalConfig;

        if (version !== this.version) {
            throw new ExPassVersionMismatchError(`Invalid version: ${version}`);
        }

        if (config.allowPreHashAlgorithms && !config.allowPreHashAlgorithms.includes(preHashAlgorithm)) {
            throw new ExPassForbidenParamValueError(`Not allowed preHashAlgorithm: ${preHashAlgorithm}`);
        } 

        if (config.allowPostHashAlgorithms && !config.allowPostHashAlgorithms.includes(postHashAlgorithm)) {
            throw new ExPassForbidenParamValueError(`Not allowed postHashAlgorithm: ${postHashAlgorithm}`);
        }

        if (config.allowHmacAlgorithms && !config.allowHmacAlgorithms.includes(hmacAlgorithm)) {
            throw new ExPassForbidenParamValueError(`Not allowed hmacAlgorithm: ${hmacAlgorithm}`);
        }

        if (config.allowCipherAlgorithms && !config.allowCipherAlgorithms.includes(cipherAlgorithm)) {
            throw new ExPassForbidenParamValueError(`Not allowed cipherAlgorithm: ${cipherAlgorithm}`);
        }

        if (config.minSaltLength && saltLength < config.minSaltLength) {
            throw new ExPassForbidenParamValueError(`Salt length is too short: ${saltLength}`);
        }

        if (config.maxSaltLength && saltLength > config.maxSaltLength) {
            throw new ExPassForbidenParamValueError(`Salt length is too long: ${saltLength}`);
        }

        if (config.minPower && power < config.minPower) {
            throw new ExPassForbidenParamValueError(`Power is too low: ${power}`);
        }

        if (config.maxPower && power > config.maxPower) {
            throw new ExPassForbidenParamValueError(`Power is too high: ${power}`);
        }

        if (config.minEncodeHashLength && encodeHashLenght < config.minEncodeHashLength) {
            throw new ExPassForbidenParamValueError(`Encode block size is too low: ${encodeHashLenght}`);
        }

        if (config.maxEncodeHashLength && encodeHashLenght > config.maxEncodeHashLength) {
            throw new ExPassForbidenParamValueError(`Encode block size is too high: ${encodeHashLenght}`);
        }

        if (config.minKeyDerivationPower && keyDerivationPower < config.minKeyDerivationPower) {
            throw new ExPassForbidenParamValueError(`Key derivation power is too low: ${keyDerivationPower}`);
        }

        if (config.maxKeyDerivationPower && keyDerivationPower > config.maxKeyDerivationPower) {
            throw new ExPassForbidenParamValueError(`Key derivation power is too high: ${keyDerivationPower}`);
        }

        if (salt.length !== saltLength) {
            throw new ExPassForbidenParamValueError(`Salt length mismatch: ${salt.length} !== ${saltLength}`);
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

