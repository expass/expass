
import { NodeScryptEncoder } from './encoder';

describe('NodeScryptEncoder', () => {
    let encoder: NodeScryptEncoder;

    beforeEach(() => {
        encoder = new NodeScryptEncoder();
    });

    it('should encode data', async () => {
        jest.setTimeout(10000);
        const data = Buffer.from('hello world');
        const salt = Buffer.from('salt');
        const power = 18;
        const length = 32;
        const encoded = await encoder.encode(data, salt, power, length);

        expect(encoded).toBeInstanceOf(Buffer);
        expect(encoded.length).toBe(length);
        expect(encoded.toString('hex')).toBe(
            '3c971eba76591d57aed2d7fda5838e76fe670d0778175f26fc8a5378942d5849'
        );
    });
});
