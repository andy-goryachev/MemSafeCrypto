# MemSafeCrypto

A subset of BouncyCastle crypto primitives refactored to use DirectByteBuffer.


## Summary of Changes

- introducted IZeroable interface
- replaced byte[] and int[] with ByteArray and IntArray correspondingly


## Supported primitives

- Salsa20Engine
- XSalsa20Engine
- Poly1305


## Original Code

https://github.com/bcgit/bc-java


## License

The project is licensed under Apache 2.0 license, which I believe is compatible with the BouncyCastle license 
[src/goryachev/memsafecrypto/bc/LICENSE.html](LICENSE.html).