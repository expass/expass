
import { scrypt } from 'crypto';
import { EncoderInterface } from '@expass/core';

export class NodeScryptEncoder implements EncoderInterface {
    async encode(data: Buffer, salt: Buffer, power: number, length: number): Promise<Buffer> {
        const cost = 2 ** power;
        const maxmem = 128 * cost * 8 * 2;
        const options = {
            cost,
            maxmem,
            parallelization: 2
        };
        return new Promise((resolve, reject) => scrypt(data, salt, length, options, (err, key) => {
            if (err) {
                return reject(err);
            }

            resolve(key);
        }));
    }
}
