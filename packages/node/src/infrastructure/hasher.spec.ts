
import { NodeHasher } from './hasher';

describe('NodeHasher', () => {

    describe('#hash', () => {

        it('Should to hash to sha256', () => {
            const hasher = new NodeHasher('sha256');
            const hash = hasher.hash(Buffer.from('hello world'));
            expect(hash).toBeInstanceOf(Buffer);
            expect(hash.toString('hex')).toBe(
                'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
            );
        });

    });

    describe('#hmac', () => {

        it('Should to hmac using sha256', () => {
            const hasher = new NodeHasher('sha256');
            const body = Buffer.from('hello world');
            const key = Buffer.from('secret key');

            const hash = hasher.hmac(body, key);
            expect(hash).toBeInstanceOf(Buffer);
            expect(hash.toString('hex')).toBe(
                'c61b5198df58639edb9892514756b89a36856d826e5d85023ab181b48ea5d018'
            );
        });

    });

});
