
import 'reflect-metadata';
import {
    randomBytes,
    timingSafeEqual,
} from 'crypto';
import {
    CryptoInterface,
    interfaces,
} from '@expass/core';
import { singleton } from 'tsyringe';
import { NodeHasher } from './hasher';
import { NodeCipher } from './cipher';
import { NodeScryptEncoder } from './encoder';

type HashAlgorithm = interfaces.HashAlgorithm;
type CipherAlgorithm = interfaces.CipherAlgorithm;
type KeyAndIv = interfaces.KeyAndIv;

const cipherAlgorithmsKeyAndIVLengths: Record<CipherAlgorithm, [number, number]> = {
    'aes-128': [16, 16],
    'aes-256': [32, 16],
};

@singleton()
export class NodeCrypto implements CryptoInterface {

    createSalt(length: number): Buffer {
        return randomBytes(length);
    }

    createHasher<A extends HashAlgorithm>(algorithm: A): NodeHasher<A> {
        return new NodeHasher(algorithm);
    }

    createCipher<A extends CipherAlgorithm>(algorithm: A): NodeCipher<A> {
        return new NodeCipher(algorithm);
    }

    async derivateKey(password: Buffer, salt: Buffer, algorithm: CipherAlgorithm, power: number): Promise<KeyAndIv> {

        if (!cipherAlgorithmsKeyAndIVLengths[algorithm]) {
            throw new Error(`Unknown cipher algorithm: ${algorithm}`);
        }

        const [keyLength, ivLength] = cipherAlgorithmsKeyAndIVLengths[algorithm];
        const encoder = new NodeScryptEncoder();
        const keyAndIvBuffer: Buffer = await encoder.encode(
            password, salt, power, keyLength + ivLength
        );

        return {
            key: keyAndIvBuffer.slice(0, keyLength),
            iv: keyAndIvBuffer.slice(keyLength, keyLength + ivLength),
        };
    }

    secureCompare(a: Buffer, b: Buffer): boolean {
        return timingSafeEqual(a, b);
    }
}
