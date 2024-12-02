# Scrypt Key Derivation Function in TypeScript

This is a TypeScript implementation of the scrypt key derivation function.

### Dependencies
```json
{
    "typescript": "^5.7.2",
    "pbkdf2": "^3.1.2"
}
```

### Tips

- `Uint32Array` is faster than `Uint8Array` for Bitwise operations.
- `new Uint32Array` is much faster than `Uint32Array.from` for copying arrays.

### Verification

[scrypt-js](https://github.com/ricmoo/scrypt-js), Pure JavaScript implementation of the scrypt password-based key derivation function.

https://ricmoo.github.io/scrypt-js/

### References
- [Scrypt - Wikipedia](https://en.wikipedia.org/wiki/Scrypt)
- [Salsa20 - Wikipedia](https://en.wikipedia.org/wiki/Salsa20)
