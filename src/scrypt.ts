// Reference: https://en.wikipedia.org/wiki/Scrypt
// Reference: https://en.wikipedia.org/wiki/Salsa20
// Dependency: {"dependencies": { "pbkdf2": "^3.1.2", "@types/pbkdf2": "^3.1.2" }}

import { pbkdf2Sync } from "pbkdf2";

export interface ScryptMaterial {
    salt: Uint8Array,
    length: number,
    n: number,
    r: number,
    p: number,
}

function ROTL(a: number, b: number): number {
    return (a << b) | (a >>> (32 - b));
}

function QR(X: Uint32Array, a: number, b: number, c: number, d: number) {
    X[b] ^= ROTL(X[a] + X[d], 7);
    X[c] ^= ROTL(X[b] + X[a], 9);
    X[d] ^= ROTL(X[c] + X[b], 13);
    X[a] ^= ROTL(X[d] + X[c], 18);
}

function salsa20R8(X: Uint32Array) {
    const B = new Uint32Array(X);
    for (let i = 0; i < 8; i += 2) {
        QR(B, 0, 4, 8, 12);
        QR(B, 5, 9, 13, 1);
        QR(B, 10, 14, 2, 6);
        QR(B, 15, 3, 7, 11);
        //
        QR(B, 0, 1, 2, 3);
        QR(B, 5, 6, 7, 4);
        QR(B, 10, 11, 8, 9);
        QR(B, 15, 12, 13, 14);
    }
    for (let i = 0; i < X.length; i++) {
        X[i] += B[i];
    }
}

function Xor_Block32(X32: Uint32Array, b: Uint32Array) {
    for (let i = 0; i < X32.length; i++) {
        X32[i] ^= b[i];
    }
}

// Convert the last 16 words (64 bytes) of the block to a little-endian number
function Integerify32(block: Uint32Array): number {
    const slice = block.subarray(block.length-16, block.length);
    const dataView = new DataView(slice.buffer, slice.byteOffset, slice.byteLength);
    return dataView.getUint32(0, true);
}

function BlockMix32(Y: Uint32Array) {
    const r = Y.length / (2*16); // to (2*r) 16-word chunks
    const B = new Uint32Array(Y);

    let X = new Uint32Array( B.subarray(B.length-16, B.length) );
    for (let i = 0; i < 2 * r; i++) {
        const Bi = B.subarray(i*16, (i+1)*16);
        Xor_Block32(X, Bi);
        salsa20R8(X);
        if (i % 2 === 0) {
            Y.set(X, 8 * i);
        } else {
            Y.set(X, 16 * r + 8 * (i-1));
        }
    }
}

function ROMix(X32: Uint32Array, iterations: number) {
    const V: Array<Uint32Array> = new Array(iterations);
    //
    for (let i = 0; i < iterations; i++) {
        V[i] = new Uint32Array(X32);
        BlockMix32(X32);
    }
    //
    for (let _ = 0; _ < iterations; _++) {
        const j = Integerify32(X32) % iterations;
        Xor_Block32(X32, V[j]);
        BlockMix32(X32);
    }
}

export function scryptKeyDerive(password: string, material: ScryptMaterial): Uint8Array {
    const blockSize = 128 * material.r;
    const dkLen = blockSize * material.p;
    const dk = pbkdf2Sync(password, material.salt, 1, dkLen, 'sha256');

    const exSalt = new Uint32Array(dkLen>>2);
    for (let i = 0; i < material.p; i++) {
        const slice = dk.subarray(i*blockSize, (i+1)*blockSize);
        const B = new Uint32Array(slice.buffer, slice.byteOffset, slice.byteLength>>2);
        ROMix(B, material.n);
        exSalt.set(B, i * blockSize>>2);
    }

    const result = pbkdf2Sync(password, exSalt, 1, material.length, 'sha256');
    return result;
}
