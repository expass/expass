
import { Encoder } from '../../domain/encoder';
import { fakeHash } from './fakehash';

export interface MockInterface {
    length: number,
    encode: jest.Mock<Buffer, [Buffer, Buffer, number]>,
    clear: () => void,
}

export const __mock: MockInterface = {
    length: 64,
    encode: jest.fn((data: Buffer, salt: Buffer, power: number) => fakeHash(Buffer.concat([data, salt]), __mock.length)),
    clear: () => {
        __mock.encode.mockClear();
    },
};

export class MockEncoder implements Encoder {

    encode(data: Buffer, salt: Buffer, power: number): Promise<Buffer> {
        return Promise.resolve(__mock.encode(data, salt, power));
    }

}

