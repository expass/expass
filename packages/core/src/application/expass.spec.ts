
import 'reflect-metadata';
import { container as tsyContainer } from 'tsyringe';
import { ExPass as ExPassInterface } from '../domain/expass';
import { MockEncoder, __mock as encoderMock } from './__mocks__/encoder';
import { MockHasher, __mock as hasherMock } from './__mocks__/hasher';
import { MockCrypto, __mock as cryptoMock } from './__mocks__/crypto';
import { MockCipher, __mock as cipherMock } from './__mocks__/cipher';
import { DefaultConfig } from './defaultconfig';
import { Packager } from './packager';
import { ExPass } from './expass';

describe('ExPass', () => {
    let container: typeof tsyContainer;
    let expass: ExPassInterface;

    beforeAll(() => {
        container = tsyContainer.createChildContainer();
        container.register('Packager', { useClass: Packager });
        container.register('Crypto', { useClass: MockCrypto });
        container.register('Encoder', { useClass: MockEncoder });
        expass = container.resolve(ExPass);
    });

    afterEach(() => {
        encoderMock.clear();
        hasherMock.clear();
        cryptoMock.clear();
        cipherMock.clear();
        container.clearInstances();
    });

    describe('#hash', () => {

        it('Should hash string data with the given algorithm', () => {
            const result = expass.hash('test', 'sha256');
            expect(cryptoMock.createHasher).toHaveBeenCalledTimes(1);
            expect(cryptoMock.createHasher).toHaveBeenCalledWith('sha256');
            expect(hasherMock.hash).toHaveBeenCalledTimes(1);
            expect(hasherMock.hash).toHaveBeenCalledWith(Buffer.from('test', 'utf8'));
            expect(result).toBeInstanceOf(Buffer);
            expect(result.toString('base64'))
                .toBe(
                    'dHNldHRzZXR0c2V0dHNldHRzZXR0c2V0dHNldHRzZXR0c2V0dHNldHRzZXR0c2V0dHNldHRzZXR0c2V0dHNldA=='
                );
        });

        it('Should hash buffer data with the given algorithm', () => {
            const result = expass.hash(Buffer.from('test'), 'sha256');
            expect(cryptoMock.createHasher).toHaveBeenCalledTimes(1);
            expect(cryptoMock.createHasher).toHaveBeenCalledWith('sha256');
            expect(hasherMock.hash).toHaveBeenCalledTimes(1);
            expect(hasherMock.hash).toHaveBeenCalledWith(Buffer.from('test', 'utf8'));
            expect(result).toBeInstanceOf(Buffer);
            expect(result.toString('base64'))
                .toBe(
                    'dHNldHRzZXR0c2V0dHNldHRzZXR0c2V0dHNldHRzZXR0c2V0dHNldHRzZXR0c2V0dHNldHRzZXR0c2V0dHNldA=='
                );
        });

        it('Should call createHasher with the given algorithm', () => {
            expass.hash('test', 'sha1');
            expect(cryptoMock.createHasher).toHaveBeenCalledTimes(1);
            expect(cryptoMock.createHasher).toHaveBeenCalledWith('sha1');
        });

    });

    describe('#hmac', () => {

        it('Should hmac buffer data with the given key and algorithm', () => {
            const result = expass.hmac(Buffer.from('test'), Buffer.from('key'), 'sha256');
            expect(cryptoMock.createHasher).toHaveBeenCalledTimes(1);
            expect(cryptoMock.createHasher).toHaveBeenCalledWith('sha256');
            expect(result).toBeInstanceOf(Buffer);
            expect(result.toString('base64'))
                .toBe(
                    'eWVrdHNldHlla3RzZXR5ZWt0c2V0eWVrdHNldHlla3RzZXR5ZWt0c2V0eWVrdHNldHlla3RzZXR5ZWt0c2V0eQ=='
                );
        });

        it('Should call createHasher with the given algorithm', () => {
            expass.hmac(Buffer.from('test'), Buffer.from('key'), 'sha1');
            expect(cryptoMock.createHasher).toHaveBeenCalledTimes(1);
            expect(cryptoMock.createHasher).toHaveBeenCalledWith('sha1');
        });

    });

    describe('#derivateSessionSalt', () => {

        it('Should derivate the session salt', () => {
            const result = expass.derivateSessionSalt(
                Buffer.from('salt'),
                Buffer.from('prehash'),
                Buffer.from('secret'),
                { ...DefaultConfig }
            );
            expect(cryptoMock.createHasher).toHaveBeenCalledTimes(1);
            expect(cryptoMock.createHasher).toHaveBeenCalledWith('sha256');
            expect(hasherMock.hmac).toHaveBeenCalledTimes(2);
            expect(hasherMock.hmac).toHaveBeenNthCalledWith(1, Buffer.from('salt'), Buffer.from('prehash'));
            expect(hasherMock.hmac).toHaveBeenNthCalledWith(2,
                expect.any(Buffer),
                Buffer.from('secret')
            );
            expect(result).toBeInstanceOf(Buffer);
            expect(result.toString('base64'))
                .toBe(
                    'dGVyY2VzbHRwcmVoYXNocw=='
                );
        });

        it('Should call createHasher with the given algorithm', () => {
            expass.derivateSessionSalt(
                Buffer.from('salt'),
                Buffer.from('prehash'),
                Buffer.from('secret'),
                { ...DefaultConfig, keyDerivationAlgorithm: 'sha1' }
            );
            expect(cryptoMock.createHasher).toHaveBeenCalledTimes(1);
            expect(cryptoMock.createHasher).toHaveBeenCalledWith('sha1');
        });

        it('Should call hmac several times until the salt length is reached', () => {
            const result = expass.derivateSessionSalt(
                Buffer.from('salt'),
                Buffer.from('prehash'),
                Buffer.from('secret'),
                { ...DefaultConfig, saltLength: 130 }
            );
            // 2 calls by derivation, 64 bytes each result
            // 130 / 64 = 2.03125, 3x2 calls are needed
            expect(hasherMock.hmac).toHaveBeenCalledTimes(6);
            expect(result).toBeInstanceOf(Buffer);
            expect(result.length).toBe(130);
        });

    });

    describe('#derivateCipherKeyIv', () => {

        it('Should derivate the cipher key and iv', async () => {
            const result = await expass.derivateCipherKeyIv(
                Buffer.from('secretSalt'),
                Buffer.from('secret'),
                { ...DefaultConfig }
            );

            expect(cryptoMock.derivateKey).toHaveBeenCalledTimes(1);
            expect(cryptoMock.derivateKey).toHaveBeenCalledWith(
                Buffer.from('secretSalt'),
                Buffer.from('secret'),
                'sha256',
                10000
            );
            expect(result).toEqual({
                key: Buffer.from('dGVyY2VzdGxhU3RlcmNlc3RlcmNlc3RsYVN0ZXJjZXM=', 'base64'),
                iv: Buffer.from('dGxhU3RlcmNlc3RlcmNlcw==', 'base64')
            });
        });

        it('Should call createHasher with the given algorithm', async () => {
            await expass.derivateCipherKeyIv(
                Buffer.from('secretSalt'),
                Buffer.from('secret'),
                { ...DefaultConfig, keyDerivationAlgorithm: 'sha1' }
            );

            expect(cryptoMock.derivateKey).toHaveBeenCalledTimes(1);
            expect(cryptoMock.derivateKey).toHaveBeenCalledWith(
                Buffer.from('secretSalt'),
                Buffer.from('secret'),
                'sha1',
                10000
            );
        });

        it('Should call derivateKey with the given iterations', async () => {
            await expass.derivateCipherKeyIv(
                Buffer.from('secretSalt'),
                Buffer.from('secret'),
                { ...DefaultConfig, keyDerivationIterations: 3242 }
            );

            expect(cryptoMock.derivateKey).toHaveBeenCalledTimes(1);
            expect(cryptoMock.derivateKey).toHaveBeenCalledWith(
                Buffer.from('secretSalt'),
                Buffer.from('secret'),
                'sha256',
                3242
            );
        });

    });

    describe('#encrypt', () => {

        it('Should encrypt data with the given key and iv', () => {
            const result = expass.encrypt(
                Buffer.from('data'),
                { key: Buffer.from('key'), iv: Buffer.from('iv') },
                { ...DefaultConfig }
            );

            expect(cryptoMock.createCipher).toHaveBeenCalledTimes(1);
            expect(cryptoMock.createCipher).toHaveBeenCalledWith('aes-256');
            expect(cipherMock.encrypt).toHaveBeenCalledTimes(1);
            expect(cipherMock.encrypt).toHaveBeenCalledWith(
                Buffer.from('data'),
                Buffer.from('key'),
                Buffer.from('iv')
            );
            expect(result).toBeInstanceOf(Buffer);
            expect(result.toString('base64'))
                .toBe(
                    'WkdGMFlRPT0='
                );
        });

        it('Should call createCipher with the given algorithm', () => {
            expass.encrypt(
                Buffer.from('data'),
                { key: Buffer.from('key'), iv: Buffer.from('iv') },
                { ...DefaultConfig, cipherAlgorithm: 'aes-128' }
            );

            expect(cryptoMock.createCipher).toHaveBeenCalledTimes(1);
            expect(cryptoMock.createCipher).toHaveBeenCalledWith('aes-128');
        });

    });

    describe('#decrypt', () => {

        it('Should decrypt data with the given key and iv', () => {
            const result = expass.decrypt(
                Buffer.from('WkdGMFlRPT0=', 'base64'),
                { key: Buffer.from('key'), iv: Buffer.from('iv') },
                { ...DefaultConfig }
            );

            expect(cryptoMock.createCipher).toHaveBeenCalledTimes(1);
            expect(cryptoMock.createCipher).toHaveBeenCalledWith('aes-256');
            expect(cipherMock.decrypt).toHaveBeenCalledTimes(1);
            expect(cipherMock.decrypt).toHaveBeenCalledWith(
                Buffer.from('WkdGMFlRPT0=', 'base64'),
                Buffer.from('key'),
                Buffer.from('iv')
            );
            expect(result).toBeInstanceOf(Buffer);
            expect(result.toString('utf8'))
                .toBe(
                    'data'
                );
        });

        it('Should call createCipher with the given algorithm', () => {
            expass.decrypt(
                Buffer.from('data'),
                { key: Buffer.from('key'), iv: Buffer.from('iv') },
                { ...DefaultConfig, cipherAlgorithm: 'aes-128' }
            );

            expect(cryptoMock.createCipher).toHaveBeenCalledTimes(1);
            expect(cryptoMock.createCipher).toHaveBeenCalledWith('aes-128');
        });

    });

    describe('#encode', () => {

        it('Should encode a string with the given secret', async () => {
            const result = await expass.encode(
                'password123',
                Buffer.from('secret'),
                { ...DefaultConfig }
            );

            // 1- preHash, 2- secretSalt (hmac), 3 - postHash
            expect(cryptoMock.createHasher).toHaveBeenCalledTimes(3);
            expect(cryptoMock.createHasher).toHaveBeenNthCalledWith(1, 'sha256');
            expect(cryptoMock.createHasher).toHaveBeenNthCalledWith(2, 'sha256');
            expect(cryptoMock.createHasher).toHaveBeenNthCalledWith(3, 'sha256');

            expect(cryptoMock.createSalt).toHaveBeenCalledTimes(1);
            expect(cryptoMock.createSalt).toHaveBeenCalledWith(16);

            expect(cryptoMock.derivateKey).toHaveBeenCalledTimes(1);
            expect(cryptoMock.derivateKey).toHaveBeenCalledWith(
                expect.any(Buffer),
                Buffer.from('secret'),
                'sha256',
                10000
            );

            expect(cryptoMock.createCipher).toHaveBeenCalledTimes(1);
            expect(cryptoMock.createCipher).toHaveBeenCalledWith('aes-256');
            
            // 1- preHash, 2- postHash
            expect(hasherMock.hash).toHaveBeenCalledTimes(2);
            expect(hasherMock.hash).toHaveBeenNthCalledWith(1, Buffer.from('password123', 'utf8'));
            expect(hasherMock.hash).toHaveBeenNthCalledWith(2, expect.any(Buffer));

            expect(encoderMock.encode).toHaveBeenCalledTimes(1);
            expect(encoderMock.encode).toHaveBeenCalledWith(
                expect.any(Buffer),
                expect.any(Buffer),
                8
            );

            expect(cipherMock.encrypt).toHaveBeenCalledTimes(1);
            expect(cipherMock.encrypt).toHaveBeenCalledWith(
                expect.any(Buffer),
                expect.any(Buffer),
                expect.any(Buffer)
            );
       });

        it('Should call createHasher with the given algorithm', async () => {
            await expass.encode(
                'password123',
                Buffer.from('secret'),
                { ...DefaultConfig, preHashAlgorithm: 'sha1' }
            );

            expect(cryptoMock.createHasher).toHaveBeenCalledTimes(3);
            expect(cryptoMock.createHasher).toHaveBeenNthCalledWith(1, 'sha1');
            expect(cryptoMock.createHasher).toHaveBeenNthCalledWith(2, 'sha256');
            expect(cryptoMock.createHasher).toHaveBeenNthCalledWith(3, 'sha256');
        });

        it('Should call createSalt with the given length', async () => {
            const result = await expass.encode(
                'password123',
                Buffer.from('secret'),
                { ...DefaultConfig, saltLength: 32 }
            );

            expect(cryptoMock.createSalt).toHaveBeenCalledTimes(1);
            expect(cryptoMock.createSalt).toHaveBeenCalledWith(32);

            expect(cryptoMock.derivateKey).toHaveBeenCalledTimes(1);
            expect(cryptoMock.derivateKey).toHaveBeenCalledWith(
                expect.any(Buffer),
                expect.any(Buffer),
                'sha256',
                10000
            );

            // 32 / 3 * 4 = 42.6... 43 bytes in base64 (widhout padding)
            expect(result).toMatch(/^\$expass\$sl=32\$A{43}\$/);
        });

    });

    describe('#compare', () => {

        it('Should compare a string with a hash', async () => {
            const result = await expass.compare(
                'password123',
                '$expass$$AAAAAAAAAAAAAAAAAAAAAA$YjNkemMyRndNekl4WkhKdmQzTnpZWEF6TWpGa2NtOTNjM05oY0RNeU1XUnliM2R6YzJGd016SXhaSEp2ZDNOemRHVnlZMlZ6TXpJeFpISnZkM056WVE9PQ',
                Buffer.from('secret'),
                { ...DefaultConfig }
            );

            expect(cryptoMock.secureCompare).toHaveBeenCalledTimes(1);
            expect(cryptoMock.secureCompare).toHaveBeenCalledWith(
                expect.any(Buffer),
                expect.any(Buffer)
            );

            expect(result).toBe(true);
        });

        it('Should return false if password is wrong', async () => {
            const result = await expass.compare(
                'passwOrd123',
                '$expass$$AAAAAAAAAAAAAAAAAAAAAA$YjNkemMyRndNekl4WkhKdmQzTnpZWEF6TWpGa2NtOTNjM05oY0RNeU1XUnliM2R6YzJGd016SXhaSEp2ZDNOemRHVnlZMlZ6TXpJeFpISnZkM056WVE9PQ',
                Buffer.from('secret'),
                { ...DefaultConfig }
            );

            expect(result).toBe(false);
        });

        it('Should return false if hash is wrong', async () => {
            const result = await expass.compare(
                'password123',
                '$expass$$AAAAAAAAAAAAAAAAAAAAAA$BBBkemMyRndNekl4WkhKdmQzTnpZWEF6TWpGa2NtOTNjM05oY0RNeU1XUnliM2R6YzJGd016SXhaSEp2ZDNOemRHVnlZMlZ6TXpJeFpISnZkM056WVE9Q',
                Buffer.from('secret'),
                { ...DefaultConfig }
            );

            expect(result).toBe(false);
        });

        it('Should throw an error if hash is invalid', async () => {
            await expect(expass.compare(
                'password123',
                'invalidhash',
                Buffer.from('secret'),
                { ...DefaultConfig }
            )).rejects.toThrow('Invalid hash');
        });

        it('Should throw an error if preHashAlgorithm is not allowed', async () => {
            await expect(expass.compare(
                'password123',
                '$expass$$AAAAAAAAAAAAAAAAAAAAAA$YjNkemMyRndNekl4WkhKdmQzTnpZWEF6TWpGa2NtOTNjM05oY0RNeU1XUnliM2R6YzJGd016SXhaSEp2ZDNOemRHVnlZMlZ6TXpJeFpISnZkM056WVE9PQ',
                Buffer.from('secret'),
                { ...DefaultConfig, allowPreHashAlgorithms: ['sha1'] }
            )).rejects.toThrow('Not allowed preHashAlgorithm: sha256');
        });

        it('Should throw an error if postHashAlgorithm is not allowed', async () => {
            await expect(expass.compare(
                'password123',
                '$expass$$AAAAAAAAAAAAAAAAAAAAAA$YjNkemMyRndNekl4WkhKdmQzTnpZWEF6TWpGa2NtOTNjM05oY0RNeU1XUnliM2R6YzJGd016SXhaSEp2ZDNOemRHVnlZMlZ6TXpJeFpISnZkM056WVE9PQ',
                Buffer.from('secret'),
                { ...DefaultConfig, allowPostHashAlgorithms: ['sha1'] }
            )).rejects.toThrow('Not allowed postHashAlgorithm: sha256');
        });

        it('Should throw an error if keyDerivationAlgorithm is not allowed', async () => {
            await expect(expass.compare(
                'password123',
                '$expass$$AAAAAAAAAAAAAAAAAAAAAA$YjNkemMyRndNekl4WkhKdmQzTnpZWEF6TWpGa2NtOTNjM05oY0RNeU1XUnliM2R6YzJGd016SXhaSEp2ZDNOemRHVnlZlZ6TXpJeFpISnZkM056WVE9PQ',
                Buffer.from('secret'),
                { ...DefaultConfig, allowKeyDerivationAlgorithms: ['sha1'] }
            )).rejects.toThrow('Not allowed keyDerivationAlgorithm: sha256');
        });

        it('Should throw an error if cipherAlgorithm is not allowed', async () => {
            await expect(expass.compare(
                'password123',
                '$expass$$AAAAAAAAAAAAAAAAAAAAAA$YjNkemMyRndNekl4WkhKdmQzTnpZWEF6TWpGa2NtOTNjM05oY0RNeU1XUnliM2R6YzJGd016SXhaSEp2ZDNOemRHVnlZlZ6TXpJeFpISnZkM056WVE9PQ',
                Buffer.from('secret'),
                { ...DefaultConfig, allowCipherAlgorithms: ['aes-128'] }
            )).rejects.toThrow('Not allowed cipherAlgorithm: aes-256');
        });

        it('Should throw an error if salt is to short', async () => {
            await expect(expass.compare(
                'password123',
                '$expass$$AAAAAAAAAAAAAAAAAAAAAA$YjNkemMyRndNekl4WkhKdmQzTnpZWEF6TWpGa2NtOTNjM05oY0RNeU1XUnliM2R6YzJGd016SXhaSEp2ZDNOemRHVnlZlZ6TXpJeFpISnZkM056WVE9PQ',
                Buffer.from('secret'),
                { ...DefaultConfig, minSaltLength: 32 }
            )).rejects.toThrow('Salt length is too short: 16');
        });

        it('Should throw an error if salt is to long', async () => {
            await expect(expass.compare(
                'password123',
                '$expass$$AAAAAAAAAAAAAAAAAAAAAA$YjNkemMyRndNekl4WkhKdmQzTnpZWEF6TWpGa2NtOTNjM05oY0RNeU1XUnliM2R6YzJGd016SXhaSEp2ZDNOemRHVnlZlZ6TXpJeFpISnZkM056WVE9PQ',
                Buffer.from('secret'),
                { ...DefaultConfig, maxSaltLength: 8 }
            )).rejects.toThrow('Salt length is too long: 16');
        });

        it('Should throw an error if power is to low', async () => {
            await expect(expass.compare(
                'password123',
                '$expass$$AAAAAAAAAAAAAAAAAAAAAA$YjNkemMyRndNekl4WkhKdmQzTnpZWEF6TWpGa2NtOTNjM05oY0RNeU1XUnliM2R6YzJGd016SXhaSEp2ZDNOemRHVnlZlZ6TXpJeFpISnZkM056WVE9PQ',
                Buffer.from('secret'),
                { ...DefaultConfig, minPower: 16 }
            )).rejects.toThrow('Power is too low: 8');
        });

        it('Should throw an error if power is to high', async () => {
            await expect(expass.compare(
                'password123',
                '$expass$$AAAAAAAAAAAAAAAAAAAAAA$YjNkemMyRndNekl4WkhKdmQzTnpZWEF6TWpGa2NtOTNjM05oY0RNeU1XUnliM2R6YzJGd016SXhaSEp2ZDNOemRHVnlZlZ6TXpJeFpISnZkM056WVE9PQ',
                Buffer.from('secret'),
                { ...DefaultConfig, maxPower: 4 }
            )).rejects.toThrow('Power is too high: 8');
        });

        it('Should throw an error if keyDerivationIterations is to low', async () => {
            await expect(expass.compare(
                'password123',
                '$expass$$AAAAAAAAAAAAAAAAAAAAAA$YjNkemMyRndNekl4WkhKdmQzTnpZWEF6TWpGa2NtOTNjM05oY0RNeU1XUnliM2R6YzJGd016SXhaSEp2ZDNOemRHVnlZlZ6TXpJeFpISnZkM056WVE9PQ',
                Buffer.from('secret'),
                { ...DefaultConfig, minKeyDerivationIterations: 15000}
            )).rejects.toThrow('Key derivation iterations is too low: 10000');
        });

        it('Should throw an error if keyDerivationIterations is to high', async () => {
            await expect(expass.compare(
                'password123',
                '$expass$$AAAAAAAAAAAAAAAAAAAAAA$YjNkemMyRndNekl4WkhKdmQzTnpZWEF6TWpGa2NtOTNjM05oY0RNeU1XUnliM2R6YzJGd016SXhaSEp2ZDNOemRHVnlZlZ6TXpJeFpISnZkM056WVE9PQ',
                Buffer.from('secret'),
                { ...DefaultConfig, maxKeyDerivationIterations: 5000 }
            )).rejects.toThrow('Key derivation iterations is too high: 10000');
        });

        it('Should throw an error if salt length mismatch', async () => {
            await expect(expass.compare(
                'password123',
                '$expass$sl=24$AAAAAAAAAAAAAAAAAAAAAA$YjNkemMyRndNekl4WkhKdmQzTnpZWEF6TWpGa2NtOTNjM05oY0RNeU1XUnliM2R6YzJGd016SXhaSEp2ZDNOemRHVnlZlZ6TXpJeFpISnZkM056WVE9PQ',
                Buffer.from('secret'),
                { ...DefaultConfig }
            )).rejects.toThrow('Salt length mismatch: 16 !== 24');
        });

    });

});
