
export interface Encoder {
    encode(data: Buffer, salt: Buffer, power: number, length: number): Promise<Buffer>;
}
