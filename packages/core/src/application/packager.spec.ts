
import { ExPassConfig } from '../domain/interfaces';
import { Packager } from './packager';
import { DefaultConfig } from './defaultconfig';

describe('Packager', () => {

    describe('#pack', () => {

        it('Should pack the salt, body and config into a string', () => {
            const salt = Buffer.from('s'.repeat(16));
            const body = Buffer.from('x'.repeat(64));
            const config : ExPassConfig = {
                ...DefaultConfig,
            };
            const packager = new Packager();
            const result = packager.pack(salt, body, config);
            expect(result).toBe(
                '$expass$$c3Nzc3Nzc3Nzc3Nzc3Nzcw$eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA'
            );
        });

        it('Should pack the salt, body and config into a string with custom preHashAlgorithm', () => {
            const salt = Buffer.from('s'.repeat(16));
            const body = Buffer.from('x'.repeat(64));
            const config : ExPassConfig = {
                ...DefaultConfig,
                preHashAlgorithm: 'sha512',
            };
            const packager = new Packager();
            const result = packager.pack(salt, body, config);
            expect(result).toBe(
                '$expass$pra=sha512$c3Nzc3Nzc3Nzc3Nzc3Nzcw$eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA'
            );
        });

        it('Should pack the salt, body and config into a string with custom config', () => {
            const salt = Buffer.from('s'.repeat(16));
            const body = Buffer.from('x'.repeat(64));
            const config : ExPassConfig = {
                preHashAlgorithm: 'sha512',
                postHashAlgorithm: 'sha512',
                saltLength: 32,
                power: 10,
                encodeBlockSize: 64,
                keyDerivationAlgorithm: 'sha512',
                keyDerivationIterations: 50000,
                cipherAlgorithm: 'aes-128',
            };
            const packager = new Packager();
            const result = packager.pack(salt, body, config);
            expect(result).toBe(
                '$expass$pra=sha512&poa=sha512&sl=32&p=10&kda=sha512&kdi=50000&ca=aes-128$c3Nzc3Nzc3Nzc3Nzc3Nzcw$eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA'
            );
        });

    });

    describe('#unpack', () => {

        it('Should unpack the string into a ExPassPackage', () => {
            const data = '$expass$$c3Nzc3Nzc3Nzc3Nzc3Nzcw$eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA';
            const packager = new Packager();
            const result = packager.unpack(data);
            expect(result).toEqual({
                salt: Buffer.from('s'.repeat(16)),
                body: Buffer.from('x'.repeat(64)),
                config: {
                    ...DefaultConfig,
                }
            });
        });

        it('Should unpack the string into a ExPassPackage with custom preHashAlgorithm', () => {
            const data = '$expass$pra=sha512$c3Nzc3Nzc3Nzc3Nzc3Nzcw$eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA'
            const packager = new Packager();
            const result = packager.unpack(data);
            expect(result).toEqual({
                salt: Buffer.from('s'.repeat(16)),
                body: Buffer.from('x'.repeat(64)),
                config: {
                    ...DefaultConfig,
                    preHashAlgorithm: 'sha512',
                }
            });
        });

        it('Should unpack the string into a ExPassPackage with custom config', () => {
            const data = '$expass$pra=sha512&poa=sha512&sl=32&p=10&kda=sha512&kdi=50000&ca=aes-128$c3Nzc3Nzc3Nzc3Nzc3Nzcw$eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA';
            const packager = new Packager();
            const result = packager.unpack(data);
            expect(result).toEqual({
                salt: Buffer.from('s'.repeat(16)),
                body: Buffer.from('x'.repeat(64)),
                config: {
                    preHashAlgorithm: 'sha512',
                    postHashAlgorithm: 'sha512',
                    saltLength: 32,
                    power: 10,
                    encodeBlockSize: 64,
                    keyDerivationAlgorithm: 'sha512',
                    keyDerivationIterations: 50000,
                    cipherAlgorithm: 'aes-128',
                }
            });
        });

        it('Should to throw if hash is invalid', () => {
            const data = '$expass$AAA$BBB$CCC$DDD';
            const packager = new Packager();
            expect(() => packager.unpack(data)).toThrow('Invalid hash format');
        });

        it('Should to throw if header is invalid', () => {
            const data = '$Ba$$BBB$CCC';
            const packager = new Packager();
            expect(() => packager.unpack(data)).toThrow('Invalid hash format');
        });

        it('Should to throw if salt is empty', () => {
            const data = '$expass$$c3Nzc3Nzc3Nzc3Nzc3Nzcw$';
            const packager = new Packager();
            expect(() => packager.unpack(data)).toThrow('Invalid hash format');
        });

        it('Should to throw if payload is empty', () => {
            const data = '$expass$AAAAA$$';
            const packager = new Packager();
            expect(() => packager.unpack(data)).toThrow('Invalid hash format');
        });

    });


});

