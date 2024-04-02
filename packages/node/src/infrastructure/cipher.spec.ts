
import { NodeCipher } from './cipher';

describe('NodeCipher', () => {

    describe('#encrypt', () => {

        it('Should to encrypt using aes-256-cbc', () => {
            const cipher = new NodeCipher('aes-256');
            const data = Buffer.from('hello world');
            const key = Buffer.from('word'.repeat(8));
            const iv = Buffer.from('drow'.repeat(4));

            const encrypted = cipher.encrypt(data, key, iv);
            expect(encrypted).toBeInstanceOf(Buffer);
            expect(encrypted.length).toBe(16);
            expect(encrypted.toString('base64')).toBe(
                'HAyFo8p9NdnRWKBhA/KF6g=='
            );
        });

        it('Should to encrypt a larger than one block', () => {
            const cipher = new NodeCipher('aes-256');
            const data = Buffer.from('hello world '.repeat(10));
            const key = Buffer.from('word'.repeat(8));
            const iv = Buffer.from('drow'.repeat(4));

            const encrypted = cipher.encrypt(data, key, iv);
            expect(encrypted).toBeInstanceOf(Buffer);
            // 12 * 10 = 120 / 16 = 7.5 = 8 blocks or 128 bytes
            expect(encrypted.length).toBe(128);
            expect(encrypted.toString('base64')).toBe(
                'oNi+FfixNIt+tfaiyWuBtRT3FDvSftsILYSuocwKdYC4vTb' +
                'rN4UaWWZtrE9YvimaJGMzowGMT/q+VD9YK/1G95el8z8xPo' +
                'WbWwVefKuRCY6a09sDcg/T+4TNtRxqBZmzgmTvAO3sDYKK+' +
                'HQanIsArZH8eH5UMteGe0WaG4E620k='
            );
        });

    });

    describe('#decrypt', () => {

        it('Should to decrypt using aes-256-cbc', () => {
            const cipher = new NodeCipher('aes-256');
            const data = Buffer.from('HAyFo8p9NdnRWKBhA/KF6g==', 'base64');
            const key = Buffer.from('word'.repeat(8));
            const iv = Buffer.from('drow'.repeat(4));

            const decrypted = cipher.decrypt(data, key, iv);
            expect(decrypted).toBeInstanceOf(Buffer);
            expect(decrypted.toString()).toBe('hello world');
        });

        it('Should to decrypt a larger than one block', () => {
            const cipher = new NodeCipher('aes-256');
            const data = Buffer.from(
                'oNi+FfixNIt+tfaiyWuBtRT3FDvSftsILYSuocwKdYC4vTb' +
                'rN4UaWWZtrE9YvimaJGMzowGMT/q+VD9YK/1G95el8z8xPo' +
                'WbWwVefKuRCY6a09sDcg/T+4TNtRxqBZmzgmTvAO3sDYKK+' +
                'HQanIsArZH8eH5UMteGe0WaG4E620k=', 'base64');
            const key = Buffer.from('word'.repeat(8));
            const iv = Buffer.from('drow'.repeat(4));

            const decrypted = cipher.decrypt(data, key, iv);
            expect(decrypted).toBeInstanceOf(Buffer);
            expect(decrypted.toString()).toBe('hello world '.repeat(10));
        });

        it('Should to fail to decrypt with wrong key', () => {
            const cipher = new NodeCipher('aes-256');
            const data = Buffer.from('HAyFo8p9NdnRWKBhA/KF6g==', 'base64');
            const key = Buffer.from('Word'.repeat(8));
            const iv = Buffer.from('drow'.repeat(4));

            expect(() => cipher.decrypt(data, key, iv))
                .toThrowError(/bad decrypt/);
        });

        it('Should to fail to decrypt with wrong iv', () => {
            const cipher = new NodeCipher('aes-256');
            const data = Buffer.from('HAyFo8p9NdnRWKBhA/KF6g==', 'base64');
            const key = Buffer.from('word'.repeat(8));
            const iv = Buffer.from('drOw'.repeat(4));

            expect(() => cipher.decrypt(data, key, iv))
                .toThrowError(/bad decrypt/);
        });
    });

});
