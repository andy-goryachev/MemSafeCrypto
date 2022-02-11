# MemSafeCrypto

A subset of BouncyCastle crypto primitives, refactored to use DirectByteBuffer
instead of primitive arrays, to avoid leaving sensitive data in memory due to internal
copying and garbage compactification done by the JVM.



## Summary of Changes

- introducted [ICryptoZeroable](src/goryachev/memsafecrypto/ICryptoZeroable.java) interface
- created CByteArray, CIntArray, and CLongArray classes based on DirectByteBuffer
- modified BouncyCastle classes to use new array types



## Supported Primitives

- Argon2
- Blake2b
- DigestRandomGenerator
- HKDFBytesGenerator
- Poly1305
- Salsa20Engine
- Scrypt
- SHA256Digest
- XSalsa20Engine



## Original Code

This project is based on BouncyCastle release 1.69:

https://github.com/bcgit/bc-java



## Projects That Use MemSafeCrypto

[SecDB](https://github.com/andy-goryachev/SecDB)

[Passwørd Safe](https://github.com/andy-goryachev/PasswordSafe)

[Access Panel](https://github.com/andy-goryachev/AccessPanelPublic)



## License

The project is licensed under Apache 2.0 license, which I believe is compatible with the BouncyCastle license 
[LICENSE.html](src/goryachev/memsafecrypto/bc/LICENSE.html).