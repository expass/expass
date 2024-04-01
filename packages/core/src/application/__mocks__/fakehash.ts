
export const fakeHash = (data: Buffer, length: number): Buffer => {
    let hash = Buffer.alloc(0);

    while (hash.length < length) {
        const reversed = Buffer.from(data).reverse();
        hash = Buffer.concat([hash, reversed]);
    }

    return hash.slice(0, length);
}

