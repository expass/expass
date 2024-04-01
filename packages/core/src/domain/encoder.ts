
export interface Encoder {
    encode(data: Buffer, salt: Buffer, power: number): Promise<Buffer>;
}
