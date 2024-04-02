
import { NodeExPass } from './nodeexpass';

const valid = '$expass$v=1$fhuNdqUJe0hmYD7uGaAbmg$G2uVgUC0CnXoEy1lxs1BXuNd1sR9MDcP07b5.FxE1fGFMW7dDk_07eSEANZ.j5qX';
const customPOA = '$expass$v=1&poa=sha1$yNP.Q5LbZWoliPPZBseu.Q$jgOHRZtcIKs0QSIKo87S1MVozlOM2kzsp2bpvO7gOBA';
const customSalt = '$expass$v=1&sl=4$1WE9Sg$9coA6Q0SltRW2WfmiSW5vh9B54OpiT.an85Xeg2jMRU5h7p_Rzt.hRh.NYv2YfHg';

describe('NodeExPass', () => {
    const secret = 'UDxv1fCm4SQ9yMGN1h7cXxhseQ5B3b1J5FhJ26m4';

    describe('#encode', () => {
        it('Should return a hash with basic configuration', async () => {
            const exPass = new NodeExPass(secret);
            const hash = await exPass.encode('password');
            expect(hash).toBeDefined();
            // salt, 16 * 4 / 3 = 21.3333, 22 bytes in base64
            // payload, 32 + 16 = 48 bytes, 64 in base64
            expect(hash).toMatch(
                /^\$expass\$v=1\$[a-zA-Z0-9\._]{22}\$[a-zA-Z0-9\._]{64}$/
            );
        });

        it('Should return a hash with custom configuration', async () => {
            const exPass = new NodeExPass(secret, {
                postHashAlgorithm: 'sha1',
            });
            const hash = await exPass.encode('password');
            expect(hash).toBeDefined();
            // salt, 16 * 4 / 3 = 21.3333, 22 bytes in base64
            expect(hash).toMatch(
                /^\$expass\$v=1&poa=sha1\$[a-zA-Z0-9\._]{22}\$[a-zA-Z0-9\._]{43}$/
            );
        });

        it('Should return a hash with custom salt configuration', async () => {
            const exPass = new NodeExPass(secret, {
                saltLength: 4,
            });
            const hash = await exPass.encode('password');
            expect(hash).toBeDefined();
            // salt, 4 * 4 / 3 = 5.3333, 6 bytes in base64
            expect(hash).toMatch(
                /^\$expass\$v=1&sl=4\$[a-zA-Z0-9\._]{6}\$[a-zA-Z0-9\._]{64}$/
            );
        });

    });

    describe('#verify', () => {
        it('Should return true for a valid hash', async () => {
            const exPass = new NodeExPass(secret);
            const result = await exPass.verify('password', valid);
            expect(result).toBe(true);
        });

        it('Should return false for an invalid hash', async () => {
            const exPass = new NodeExPass(secret);
            const result = await exPass.verify('password', valid.replace('uGaAbmg', 'invalid'));
            expect(result).toBe(false);
        });

        it('Should thrown an error for salt length limitation', async () => {
            const exPass = new NodeExPass(secret, {
                minSaltLength: 8,
            });
            await expect(exPass.verify(
                'password',
                customSalt,
            )).rejects.toThrow('Salt length is too short');
        });

    });

});
