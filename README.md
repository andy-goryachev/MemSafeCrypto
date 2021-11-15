# MemSafeCrypto

A subset of BouncyCastle crypto primitives refactored to use DirectByteBuffer.


## Summary of Changes

- introducted ICryptoZeroable interface
- replaced byte[] and int[] with ByteArray and IntArray correspondingly
- modified BouncyCastle classes to use ByteArray and IntArray instead or primitive arrays


## Supported primitives

- Salsa20Engine
- XSalsa20Engine
- Poly1305


## Original Code

This project is based on BouncyCastle release 1.69:

https://github.com/bcgit/bc-java


## License

The project is licensed under Apache 2.0 license, which I believe is compatible with the BouncyCastle license 
[LICENSE.html](src/goryachev/memsafecrypto/bc/LICENSE.html).