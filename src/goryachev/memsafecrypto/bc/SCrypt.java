package goryachev.memsafecrypto.bc;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.CIntArray;
import goryachev.memsafecrypto.Crypto;
import goryachev.memsafecrypto.util.CUtils;


/**
 * Implementation of the scrypt a password-based key derivation function.
 * <p>
 * Scrypt was created by Colin Percival and is specified in 
 * <a href="https://tools.ietf.org/html/rfc7914">RFC 7914 - The scrypt Password-Based Key Derivation Function</a>
 */
public class SCrypt
{
	private SCrypt()
	{
		// not used.
	}


	/**
	 * Generate a key using the scrypt key derivation function.
	 *
	 * @param passphrase - the bytes of the pass phrase.
	 * @param sale - the salt to use for this invocation.
	 * @param N     CPU/Memory cost parameter. Must be larger than 1, a power of 2 and less than
	 *              <code>2^(128 * r / 8)</code>.
	 * @param r     the block size, must be &gt;= 1.
	 * @param p     Parallelization parameter. Must be a positive integer less than or equal to
	 *              <code>Integer.MAX_VALUE / (128 * r * 8)</code>.
	 * @param dkLen the length of the key to generate, in bytes.
	 * @return the generated key.
	 */
	public static CByteArray generate(CByteArray passphrase, CByteArray salt, int N, int r, int p, int dkLen)
	{
		if(passphrase == null)
		{
			throw new IllegalArgumentException("Passphrase must be provided.");
		}
		
		if(salt == null)
		{
			throw new IllegalArgumentException("Salt must be provided.");
		}
		
		if(N <= 1 || !isPowerOf2(N))
		{
			throw new IllegalArgumentException("Cost parameter N must be > 1 and a power of 2");
		}
		
		// Only value of r that cost (as an int) could be exceeded for is 1
		if(r == 1 && N >= 65536)
		{
			throw new IllegalArgumentException("Cost parameter N must be > 1 and < 65536.");
		}
		
		if(r < 1)
		{
			throw new IllegalArgumentException("Block size r must be >= 1.");
		}
		
		int maxParallel = Integer.MAX_VALUE / (128 * r * 8);
		if(p < 1 || p > maxParallel)
		{
			throw new IllegalArgumentException("Parallelisation parameter p must be >= 1 and <= " + maxParallel + " (based on block size r of " + r + ")");
		}
		
		if(dkLen < 1)
		{
			throw new IllegalArgumentException("Generated key length dkLen must be >= 1.");
		}
		
		return MFcrypt(passphrase, salt, N, r, p, dkLen);
	}


	private static CByteArray MFcrypt(CByteArray P, CByteArray S, int N, int r, int p, int dkLen)
	{
		int MFLenBytes = r * 128;
		CByteArray bytes = SingleIterationPBKDF2(P, S, p * MFLenBytes);

		CIntArray B = null;

		try
		{
			int BLen = bytes.length() >>> 2;
			B = new CIntArray(BLen);

			CUtils.littleEndianToInt(bytes, 0, B);
			
			/*
			 * Chunk memory allocations; We choose 'd' so that there will be 2**d chunks, each not
			 * larger than 32KiB, except that the minimum chunk size is 2 * r * 32.
			 */
			int d = 0, total = N * r;
			while((N - d) > 2 && total > (1 << 10))
			{
				++d;
				total >>>= 1;
			}

			int MFLenWords = MFLenBytes >>> 2;
			for(int BOff = 0; BOff < BLen; BOff += MFLenWords)
			{
				// TODO These can be done in parallel threads
				SMix(B, BOff, N, d, r);
			}

			CUtils.intToLittleEndian(B, bytes, 0);

			return SingleIterationPBKDF2(P, bytes, dkLen);
		}
		finally
		{
			bytes.zero();
			Crypto.zero(B);
		}
	}


	private static CByteArray SingleIterationPBKDF2(CByteArray P, CByteArray S, int dkLen)
	{
		PKCS5S2ParametersGenerator pGen = new PKCS5S2ParametersGenerator(new SHA256Digest());
		pGen.init(P, S, 1);
		return pGen.generateDerivedKey(dkLen);
	}


	private static void SMix(CIntArray B, int BOff, int N, int d, int r)
	{
		int powN = Integer.numberOfTrailingZeros(N);
		int blocksPerChunk = N >>> d;
		int chunkCount = 1 << d, chunkMask = blocksPerChunk - 1, chunkPow = powN - d;

		int BCount = r * 32;

		CIntArray blockX1 = new CIntArray(16);
		CIntArray blockX2 = new CIntArray(16);
		CIntArray blockY = new CIntArray(BCount);

		CIntArray X = new CIntArray(BCount);
		CIntArray[] VV = new CIntArray[chunkCount];

		try
		{
			CUtils.arraycopy(B, BOff, X, 0, BCount);

			for(int c = 0; c < chunkCount; ++c)
			{
				CIntArray V = new CIntArray(blocksPerChunk * BCount);
				VV[c] = V;

				int off = 0;
				for(int i = 0; i < blocksPerChunk; i += 2)
				{
					CUtils.arraycopy(X, 0, V, off, BCount);
					off += BCount;
					BlockMix(X, blockX1, blockX2, blockY, r);
					CUtils.arraycopy(blockY, 0, V, off, BCount);
					off += BCount;
					BlockMix(blockY, blockX1, blockX2, X, r);
				}
			}

			int mask = N - 1;
			for(int i = 0; i < N; ++i)
			{
				int j = X.get(BCount - 16) & mask;
				CIntArray V = VV[j >>> chunkPow];
				int VOff = (j & chunkMask) * BCount;
				CUtils.arraycopy(V, VOff, blockY, 0, BCount);
				Xor(blockY, X, 0, blockY);
				BlockMix(blockY, blockX1, blockX2, X, r);
			}

			CUtils.arraycopy(X, 0, B, BOff, BCount);
		}
		finally
		{
			ClearAll(VV);
			
			X.zero();
			blockX1.zero();
			blockX2.zero();
			blockY.zero();
		}
	}


	private static void BlockMix(CIntArray B, CIntArray X1, CIntArray X2, CIntArray Y, int r)
	{
		CUtils.arraycopy(B, B.length() - 16, X1, 0, 16);

		int BOff = 0, YOff = 0, halfLen = B.length() >>> 1;

		for(int i=2*r; i>0; --i)
		{
			Xor(X1, B, BOff, X2);

			Salsa20Engine.salsaCore(8, X2, X1);
			CUtils.arraycopy(X1, 0, Y, YOff, 16);

			YOff = halfLen + BOff - YOff;
			BOff += 16;
		}
	}


	private static void Xor(CIntArray a, CIntArray b, int bOff, CIntArray output)
	{
		for(int i=output.length()-1; i>=0; --i)
		{
			output.set(i, a.get(i) ^ b.get(bOff + i));
		}
	}
	
	
	private static void ClearAll(CIntArray[] arrays)
	{
		for(int i=0; i<arrays.length; ++i)
		{
			Crypto.zero(arrays[i]);
		}
	}


	// note: we know X is non-zero
	private static boolean isPowerOf2(int x)
	{
		return ((x & (x - 1)) == 0);
	}
}
