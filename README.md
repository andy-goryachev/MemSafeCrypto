# MemSafeCrypto

A subset of BouncyCastle crypto primitives, refactored to use DirectByteBuffer
instead of primitive arrays.


## Summary of Changes

- introducted ICryptoZeroable interface
- created CByteArray, CIntArray, and CLongArray classes based on DirectByteBuffer
- modified BouncyCastle classes to use new array types


## Supported primitives

- Blake2b
- Poly1305
- Salsa20Engine
- XSalsa20Engine


## Original Code

This project is based on BouncyCastle release 1.69:

https://github.com/bcgit/bc-java


## License

The project is licensed under Apache 2.0 license, which I believe is compatible with the BouncyCastle license 
[LICENSE.html](src/goryachev/memsafecrypto/bc/LICENSE.html).