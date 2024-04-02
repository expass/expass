
import { interfaces } from '@expass/core';
import { NodeCrypto } from './crypto'; 
import { NodeHasher } from './hasher';
import { NodeCipher } from './cipher';

type CipherAlgorithm = interfaces.CipherAlgorithm;

describe('NodeCrypto', () => {

    describe('createSalt', () => {
        it('Should return a random buffer', () => {
            const crypto = new NodeCrypto();
            const salt = crypto.createSalt(16);
            expect(salt.length).toBe(16);
        });
    });

    describe('createHasher', () => {
        it('Should return a NodeHasher', () => {
            const crypto = new NodeCrypto();
            const hasher = crypto.createHasher('sha256');
            expect(hasher).toBeInstanceOf(NodeHasher);
        });
    });

    describe('createCipher', () => {
        it('Should return a NodeCipher', () => {
            const crypto = new NodeCrypto();
            const cipher = crypto.createCipher('aes-256');
            expect(cipher).toBeInstanceOf(NodeCipher);
        });
    });

    describe('derivateKey', () => {
        it('Should return a key and iv for aes-256', async () => {
            const crypto = new NodeCrypto();
            const keyIv = await crypto.derivateKey(
                Buffer.from('password'),
                Buffer.from('salt'),
                'aes-256',
                10
            );

            expect(keyIv.key.length).toBe(32);
            expect(keyIv.iv.length).toBe(16);
            expect(keyIv.key.toString('hex')).toBe(
                '1765486cf4c5597fb5308d16b99794d7d3a0bd2e9464b9acb1ca32031a85dfed'
            );
            expect(keyIv.iv.toString('hex')).toBe(
                '7a333038c5283e1b1a9213f632dfa482'
            );
        });

        it('Should return a key and iv for aes-128', async () => {
            const crypto = new NodeCrypto();
            const keyIv = await crypto.derivateKey(
                Buffer.from('password'),
                Buffer.from('salt'),
                'aes-128',
                10
            );

            expect(keyIv.key.length).toBe(16);
            expect(keyIv.iv.length).toBe(16);
            expect(keyIv.key.toString('hex')).toBe(
                '1765486cf4c5597fb5308d16b99794d7',
            );
            expect(keyIv.iv.toString('hex')).toBe(
                'd3a0bd2e9464b9acb1ca32031a85dfed'
            );
        });

        it('Should throw an error if algorithm is unknown', async () => {
            const crypto = new NodeCrypto();
            await expect(crypto.derivateKey(
                Buffer.from('password'),
                Buffer.from('salt'),
                'unknown' as CipherAlgorithm,
                10
            )).rejects.toThrow('Unknown cipher algorithm: unknown');
        });
    });

    describe('secureCompare', () => {
        it('Should return true if buffers are equal', () => {
            const crypto = new NodeCrypto();
            const a = Buffer.from('hello');
            const b = Buffer.from('hello');
            expect(crypto.secureCompare(a, b)).toBe(true);
        });

        it('Should return false if buffers are not equal', () => {
            const crypto = new NodeCrypto();
            const a = Buffer.from('hello');
            const b = Buffer.from('world');
            expect(crypto.secureCompare(a, b)).toBe(false);
        });
    });

});
