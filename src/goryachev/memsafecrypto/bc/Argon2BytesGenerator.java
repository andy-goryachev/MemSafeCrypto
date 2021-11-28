package goryachev.memsafecrypto.bc;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.CCharArray;
import goryachev.memsafecrypto.CLongArray;
import goryachev.memsafecrypto.Crypto;
import goryachev.memsafecrypto.util.CUtils;


/**
 * Argon2 PBKDF - Based on the results of https://password-hashing.net/ and https://www.ietf.org/archive/id/draft-irtf-cfrg-argon2-03.txt
 * 
 * @see https://en.wikipedia.org/wiki/Argon2
 */
public class Argon2BytesGenerator
{
	private static final int ARGON2_BLOCK_SIZE = 1024;
	private static final int ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 8;

	private static final int ARGON2_ADDRESSES_IN_BLOCK = 128;

	private static final int ARGON2_PREHASH_DIGEST_LENGTH = 64;
	private static final int ARGON2_PREHASH_SEED_LENGTH = 72;

	private static final int ARGON2_SYNC_POINTS = 4;

	/* Minimum and maximum number of lanes (degree of parallelism) */
	private static final int MIN_PARALLELISM = 1;
	private static final int MAX_PARALLELISM = 16777216;

	/* Minimum and maximum digest size in bytes */
	private static final int MIN_OUTLEN = 4;

	/* Minimum and maximum number of passes */
	private static final int MIN_ITERATIONS = 1;

	private static final long M32L = 0xFFFFFFFFL;

	private static final CByteArray ZERO_BYTES = new CByteArray(4);

	private Argon2Parameters parameters;
	private Block[] memory;
	private int segmentLength;
	private int laneLength;


	public Argon2BytesGenerator()
	{
	}


	/**
	 * Initialise the Argon2BytesGenerator from the parameters.
	 *
	 * @param parameters Argon2 configuration.
	 */
	public void init(Argon2Parameters parameters)
	{
		this.parameters = parameters;

		if(parameters.getLanes() < Argon2BytesGenerator.MIN_PARALLELISM)
		{
			throw new IllegalStateException("lanes must be greater than " + Argon2BytesGenerator.MIN_PARALLELISM);
		}
		else if(parameters.getLanes() > Argon2BytesGenerator.MAX_PARALLELISM)
		{
			throw new IllegalStateException("lanes must be less than " + Argon2BytesGenerator.MAX_PARALLELISM);
		}
		else if(parameters.getMemory() < 2 * parameters.getLanes())
		{
			throw new IllegalStateException("memory is less than: " + (2 * parameters.getLanes()) + " expected " + (2 * parameters.getLanes()));
		}
		else if(parameters.getIterations() < Argon2BytesGenerator.MIN_ITERATIONS)
		{
			throw new IllegalStateException("iterations is less than: " + Argon2BytesGenerator.MIN_ITERATIONS);
		}

		doInit(parameters);
	}


	public int generateBytes(CCharArray password, CByteArray out)
	{
		CByteArray pw = parameters.getCharToByteConverter().convert(password);
		try
		{
			return generateBytes(pw, out);
		}
		finally
		{
			Crypto.zero(pw);
		}
	}


	public int generateBytes(CCharArray password, CByteArray out, int outOff, int outLen)
	{
		CByteArray pw = parameters.getCharToByteConverter().convert(password);
		try
		{
			return generateBytes(pw, out, outOff, outLen);
		}
		finally
		{
			Crypto.zero(pw);
		}
	}


	public int generateBytes(CByteArray password, CByteArray out)
	{
		return generateBytes(password, out, 0, out.length());
	}


	public int generateBytes(CByteArray password, CByteArray out, int outOff, int outLen)
	{
		if(outLen < Argon2BytesGenerator.MIN_OUTLEN)
		{
			throw new IllegalStateException("output length less than " + Argon2BytesGenerator.MIN_OUTLEN);
		}

		CByteArray tmpBlockBytes = new CByteArray(ARGON2_BLOCK_SIZE);
		try
		{
			initialize(tmpBlockBytes, password, outLen);
			fillMemoryBlocks();
			digest(tmpBlockBytes, out, outOff, outLen);
	
			reset();
	
			return outLen;
		}
		finally
		{
			tmpBlockBytes.zero();
		}
	}


	// Clear memory.
	private void reset()
	{
		// Reset memory.
		if(null != memory)
		{
			for(int i=0; i<memory.length; i++)
			{
				Block b = memory[i];
				if(null != b)
				{
					b.clear();
				}
			}
		}
	}


	private void doInit(Argon2Parameters parameters)
	{
		/* 2. Align memory size */
		/* Minimum memoryBlocks = 8L blocks, where L is the number of lanes */
		int memoryBlocks = parameters.getMemory();

		if(memoryBlocks < 2 * Argon2BytesGenerator.ARGON2_SYNC_POINTS * parameters.getLanes())
		{
			memoryBlocks = 2 * Argon2BytesGenerator.ARGON2_SYNC_POINTS * parameters.getLanes();
		}

		this.segmentLength = memoryBlocks / (parameters.getLanes() * Argon2BytesGenerator.ARGON2_SYNC_POINTS);
		this.laneLength = segmentLength * Argon2BytesGenerator.ARGON2_SYNC_POINTS;

		/* Ensure that all segments have equal length */
		memoryBlocks = segmentLength * (parameters.getLanes() * Argon2BytesGenerator.ARGON2_SYNC_POINTS);

		initMemory(memoryBlocks);
	}


	private void initMemory(int memoryBlocks)
	{
		this.memory = new Block[memoryBlocks];

		for(int i=0; i<memory.length; i++)
		{
			memory[i] = new Block();
		}
	}


	private void fillMemoryBlocks()
	{
		FillBlock filler = new FillBlock();
		Position position = new Position();
		for(int pass=0; pass<parameters.getIterations(); ++pass)
		{
			position.pass = pass;

			for(int slice=0; slice<ARGON2_SYNC_POINTS; ++slice)
			{
				position.slice = slice;

				for(int lane=0; lane<parameters.getLanes(); ++lane)
				{
					position.lane = lane;

					fillSegment(filler, position);
				}
			}
		}
	}


	private void fillSegment(FillBlock filler, Position position)
	{
		Block addressBlock = null, inputBlock = null;

		boolean dataIndependentAddressing = isDataIndependentAddressing(position);
		int startingIndex = getStartingIndex(position);
		int currentOffset = position.lane * laneLength + position.slice * segmentLength + startingIndex;
		int prevOffset = getPrevOffset(currentOffset);

		if(dataIndependentAddressing)
		{
			addressBlock = filler.addressBlock.clear();
			inputBlock = filler.inputBlock.clear();

			initAddressBlocks(filler, position, inputBlock, addressBlock);
		}

		final boolean withXor = isWithXor(position);

		for(int index=startingIndex; index<segmentLength; ++index)
		{
			long pseudoRandom = getPseudoRandom(filler, index, addressBlock, inputBlock, prevOffset, dataIndependentAddressing);
			int refLane = getRefLane(position, pseudoRandom);
			int refColumn = getRefColumn(position, index, pseudoRandom, refLane == position.lane);

			/* 2 Creating a new block */
			Block prevBlock = memory[prevOffset];
			Block refBlock = memory[((laneLength) * refLane + refColumn)];
			Block currentBlock = memory[currentOffset];

			if(withXor)
			{
				filler.fillBlockWithXor(prevBlock, refBlock, currentBlock);
			}
			else
			{
				filler.fillBlock(prevBlock, refBlock, currentBlock);
			}

			prevOffset = currentOffset;
			currentOffset++;
		}
	}


	private boolean isDataIndependentAddressing(Position position)
	{
		return 
			(parameters.getType() == Argon2Parameters.ARGON2_i) ||
			(
				parameters.getType() == Argon2Parameters.ARGON2_id &&
				(position.pass == 0) && 
				(position.slice < ARGON2_SYNC_POINTS / 2)
			);
	}


	private void initAddressBlocks(FillBlock filler, Position position, Block inputBlock, Block addressBlock)
	{
		inputBlock.v.set(0, intToLong(position.pass));
		inputBlock.v.set(1, intToLong(position.lane));
		inputBlock.v.set(2, intToLong(position.slice));
		inputBlock.v.set(3, intToLong(memory.length));
		inputBlock.v.set(4, intToLong(parameters.getIterations()));
		inputBlock.v.set(5, intToLong(parameters.getType()));

		if((position.pass == 0) && (position.slice == 0))
		{
			/* Don't forget to generate the first block of addresses: */
			nextAddresses(filler, inputBlock, addressBlock);
		}
	}


	private boolean isWithXor(Position position)
	{
		return !(position.pass == 0 || parameters.getVersion() == Argon2Parameters.ARGON2_VERSION_10);
	}


	private int getPrevOffset(int currentOffset)
	{
		if(currentOffset % laneLength == 0)
		{
			/* Last block in this lane */
			return currentOffset + laneLength - 1;
		}
		else
		{
			/* Previous block */
			return currentOffset - 1;
		}
	}


	private static int getStartingIndex(Position position)
	{
		if((position.pass == 0) && (position.slice == 0))
		{
			return 2; /* we have already generated the first two blocks */
		}
		else
		{
			return 0;
		}
	}


	private void nextAddresses(FillBlock filler, Block inputBlock, Block addressBlock)
	{
		inputBlock.v.increment(6);
		filler.fillBlock(inputBlock, addressBlock);
		filler.fillBlock(addressBlock, addressBlock);
	}


	/* 1.2 Computing the index of the reference block */
	/* 1.2.1 Taking pseudo-random value from the previous block */
	private long getPseudoRandom(FillBlock filler, int index, Block addressBlock, Block inputBlock, int prevOffset, boolean dataIndependentAddressing)
	{
		if(dataIndependentAddressing)
		{
			int addressIndex = index % ARGON2_ADDRESSES_IN_BLOCK;
			if(addressIndex == 0)
			{
				nextAddresses(filler, inputBlock, addressBlock);
			}
			return addressBlock.v.get(addressIndex);
		}
		else
		{
			return memory[prevOffset].v.get(0);
		}
	}


	private int getRefLane(Position position, long pseudoRandom)
	{
		int refLane = (int)(((pseudoRandom >>> 32)) % parameters.getLanes());

		if((position.pass == 0) && (position.slice == 0))
		{
			/* Can not reference other lanes yet */
			refLane = position.lane;
		}
		return refLane;
	}


	private int getRefColumn(Position position, int index, long pseudoRandom, boolean sameLane)
	{
		int referenceAreaSize;
		int startPosition;

		if(position.pass == 0)
		{
			startPosition = 0;

			if(sameLane)
			{
				/* The same lane => add current segment */
				referenceAreaSize = position.slice * segmentLength + index - 1;
			}
			else
			{
				/* pass == 0 && !sameLane => position.slice > 0*/
				referenceAreaSize = position.slice * segmentLength + ((index == 0) ? (-1) : 0);
			}
		}
		else
		{
			startPosition = ((position.slice + 1) * segmentLength) % laneLength;

			if(sameLane)
			{
				referenceAreaSize = laneLength - segmentLength + index - 1;
			}
			else
			{
				referenceAreaSize = laneLength - segmentLength + ((index == 0) ? (-1) : 0);
			}
		}

		long relativePosition = pseudoRandom & 0xFFFFFFFFL;
		relativePosition = (relativePosition * relativePosition) >>> 32;
		relativePosition = referenceAreaSize - 1 - ((referenceAreaSize * relativePosition) >>> 32);

		return (int)(startPosition + relativePosition) % laneLength;
	}


	private void digest(CByteArray tmpBlockBytes, CByteArray out, int outOff, int outLen)
	{
		Block finalBlock = memory[laneLength - 1];

		/* XOR the last blocks */
		for(int i=1; i<parameters.getLanes(); i++)
		{
			int lastBlockInLane = i * laneLength + (laneLength - 1);
			finalBlock.xorWith(memory[lastBlockInLane]);
		}

		finalBlock.toBytes(tmpBlockBytes);

		hash(tmpBlockBytes, out, outOff, outLen);
	}


	/**
	 * H' - hash - variable length hash function
	 */
	private void hash(CByteArray input, CByteArray out, int outOff, int outLen)
	{
		byte[] outLenBytes = new byte[4];
		CUtils.intToLittleEndian(outLen, outLenBytes, 0);

		int blake2bLength = 64;

		if(outLen <= blake2bLength)
		{
			Blake2bDigest blake = new Blake2bDigest(outLen * 8);

			blake.update(outLenBytes, 0, outLenBytes.length);
			blake.update(input, 0, input.length());
			blake.doFinal(out, outOff);
		}
		else
		{
			Blake2bDigest digest = new Blake2bDigest(blake2bLength * 8);
			byte[] outBuffer = new byte[blake2bLength];

			/* V1 */
			digest.update(outLenBytes, 0, outLenBytes.length);
			digest.update(input, 0, input.length());
			digest.doFinal(outBuffer, 0);

			int halfLen = blake2bLength / 2, outPos = outOff;
			CUtils.arraycopy(outBuffer, 0, out, outPos, halfLen);
			outPos += halfLen;

			int r = ((outLen + 31) / 32) - 2;

			for(int i = 2; i <= r; i++,outPos += halfLen)
			{
				/* V2 to Vr */
				digest.update(outBuffer, 0, outBuffer.length);
				digest.doFinal(outBuffer, 0);

				CUtils.arraycopy(outBuffer, 0, out, outPos, halfLen);
			}

			int lastLength = outLen - 32 * r;

			/* Vr+1 */
			digest = new Blake2bDigest(lastLength * 8);

			digest.update(outBuffer, 0, outBuffer.length);
			digest.doFinal(out, outPos);
		}
	}


	protected static void roundFunction(Block block, int v0, int v1, int v2, int v3, int v4, int v5, int v6, int v7, int v8, int v9, int v10, int v11, int v12, int v13, int v14, int v15)
	{
		final CLongArray v = block.v;

		F(v, v0, v4, v8, v12);
		F(v, v1, v5, v9, v13);
		F(v, v2, v6, v10, v14);
		F(v, v3, v7, v11, v15);

		F(v, v0, v5, v10, v15);
		F(v, v1, v6, v11, v12);
		F(v, v2, v7, v8, v13);
		F(v, v3, v4, v9, v14);
	}


	private static void F(CLongArray v, int a, int b, int c, int d)
	{
		quarterRound(v, a, b, d, 32);
		quarterRound(v, c, d, b, 24);
		quarterRound(v, a, b, d, 16);
		quarterRound(v, c, d, b, 63);
	}


	private static void quarterRound(CLongArray v, int x, int y, int z, int s)
	{
		//        fBlaMka(v, x, y);
		//        rotr64(v, z, x, s);

		long a = v.get(x);
		long b = v.get(y);
		long c = v.get(z);

		a += b + 2 * (a & M32L) * (b & M32L);
		c = Long.rotateRight(c ^ a, s);

		v.set(x, a);
		v.set(z, c);
	}
	

	/*designed by the Lyra PHC team */
	/* a <- a + b + 2*aL*bL
	 * + == addition modulo 2^64
	 * aL = least 32 bit */
	//    private static void fBlaMka(long[] v, int x, int y)
	//    {
	//        final long a = v[x], b = v[y];
	//        final long ab = (a & M32L) * (b & M32L);
	//
	//        v[x] = a + b + 2 * ab;
	//    }
	//
	//    private static void rotr64(long[] v, int x, int y, int s)
	//    {
	//        v[x] = Longs.rotateRight(v[x] ^ v[y], s);
	//    }


	private void initialize(CByteArray tmpBlockBytes, CByteArray password, int outputLength)
	{
		/**
		 * H0 = H64(p, τ, m, t, v, y, |P|, P, |S|, S, |L|, K, |X|, X)
		 * -> 64 byte (ARGON2_PREHASH_DIGEST_LENGTH)
		 */
		Blake2bDigest blake = new Blake2bDigest(ARGON2_PREHASH_DIGEST_LENGTH * 8);

		int[] values =
		{
			parameters.getLanes(),
			outputLength,
			parameters.getMemory(),
			parameters.getIterations(),
			parameters.getVersion(),
			parameters.getType()
		};

		CUtils.intToLittleEndian(values, tmpBlockBytes, 0);
		blake.update(tmpBlockBytes, 0, values.length * 4);
		
		CByteArray additional = parameters.getAdditional();
		try
		{
			CByteArray secret = parameters.getSecret();
			try
			{
				addByteString(tmpBlockBytes, blake, password);
				addByteString(tmpBlockBytes, blake, parameters.getSalt());
				addByteString(tmpBlockBytes, blake, secret);
				addByteString(tmpBlockBytes, blake, additional);
			}
			finally
			{
				Crypto.zero(secret);
			}
		}
		finally
		{
			Crypto.zero(additional);
		}
		
		CByteArray initialHashWithZeros = new CByteArray(ARGON2_PREHASH_SEED_LENGTH);
		blake.doFinal(initialHashWithZeros, 0);

		fillFirstBlocks(tmpBlockBytes, initialHashWithZeros);
	}


	private static void addByteString(CByteArray tmpBlockBytes, Digest digest, CByteArray octets)
	{
		if(null == octets)
		{
			digest.update(ZERO_BYTES, 0, 4);
			return;
		}

		CUtils.intToLittleEndian(octets.length(), tmpBlockBytes, 0);
		digest.update(tmpBlockBytes, 0, 4);
		digest.update(octets, 0, octets.length());
	}


	/**
	 * (H0 || 0 || i) 72 byte -> 1024 byte
	 * (H0 || 1 || i) 72 byte -> 1024 byte
	 */
	private void fillFirstBlocks(CByteArray tmpBlockBytes, CByteArray initialHashWithZeros)
	{
		CByteArray initialHashWithOnes = new CByteArray(ARGON2_PREHASH_SEED_LENGTH);
		CUtils.arraycopy(initialHashWithZeros, 0, initialHashWithOnes, 0, ARGON2_PREHASH_DIGEST_LENGTH);
		initialHashWithOnes.set(ARGON2_PREHASH_DIGEST_LENGTH, (byte)1);

		for(int i=0; i<parameters.getLanes(); i++)
		{
			CUtils.intToLittleEndian(i, initialHashWithZeros, ARGON2_PREHASH_DIGEST_LENGTH + 4);
			CUtils.intToLittleEndian(i, initialHashWithOnes, ARGON2_PREHASH_DIGEST_LENGTH + 4);

			hash(initialHashWithZeros, tmpBlockBytes, 0, ARGON2_BLOCK_SIZE);
			memory[i * laneLength + 0].fromBytes(tmpBlockBytes);

			hash(initialHashWithOnes, tmpBlockBytes, 0, ARGON2_BLOCK_SIZE);
			memory[i * laneLength + 1].fromBytes(tmpBlockBytes);
		}
	}


	private static long intToLong(int x)
	{
		return (x & M32L);
	}


	//


	protected static class FillBlock
	{
		Block R = new Block();
		Block Z = new Block();
		Block addressBlock = new Block();
		Block inputBlock = new Block();
		

		private void applyBlake()
		{
			/* Apply Blake2 on columns of 64-bit words: (0,1,...,15) , then
			(16,17,..31)... finally (112,113,...127) */
			for(int i = 0; i < 8; i++)
			{

				int i16 = 16 * i;
				roundFunction(Z, i16, i16 + 1, i16 + 2, i16 + 3, i16 + 4, i16 + 5, i16 + 6, i16 + 7, i16 + 8, i16 + 9, i16 + 10, i16 + 11, i16 + 12, i16 + 13, i16 + 14, i16 + 15);
			}

			/* Apply Blake2 on rows of 64-bit words: (0,1,16,17,...112,113), then
			(2,3,18,19,...,114,115).. finally (14,15,30,31,...,126,127) */
			for(int i = 0; i < 8; i++)
			{

				int i2 = 2 * i;
				roundFunction(Z, i2, i2 + 1, i2 + 16, i2 + 17, i2 + 32, i2 + 33, i2 + 48, i2 + 49, i2 + 64, i2 + 65, i2 + 80, i2 + 81, i2 + 96, i2 + 97, i2 + 112, i2 + 113);
			}
		}


		protected void fillBlock(Block Y, Block currentBlock)
		{
			Z.copyBlock(Y);
			applyBlake();
			currentBlock.xor(Y, Z);
		}


		protected void fillBlock(Block X, Block Y, Block currentBlock)
		{
			R.xor(X, Y);
			Z.copyBlock(R);
			applyBlake();
			currentBlock.xor(R, Z);
		}


		protected void fillBlockWithXor(Block X, Block Y, Block currentBlock)
		{
			R.xor(X, Y);
			Z.copyBlock(R);
			applyBlake();
			currentBlock.xorWith(R, Z);
		}
	}


	//


	protected static class Block
	{
		private static final int SIZE = ARGON2_QWORDS_IN_BLOCK;
		/* 128 * 8 Byte QWords */
		protected final CLongArray v;


		protected Block()
		{
			v = new CLongArray(SIZE);
		}


		void fromBytes(CByteArray input)
		{
			if(input.length() < ARGON2_BLOCK_SIZE)
			{
				throw new IllegalArgumentException("input shorter than blocksize");
			}

			CUtils.littleEndianToLong(input, 0, v);
		}


		void toBytes(CByteArray output)
		{
			if(output.length() < ARGON2_BLOCK_SIZE)
			{
				throw new IllegalArgumentException("output shorter than blocksize");
			}

			CUtils.longToLittleEndian(v, output, 0);
		}


		protected void copyBlock(Block other)
		{
			CUtils.arraycopy(other.v, 0, v, 0, SIZE);
		}


		protected void xor(Block b1, Block b2)
		{
			CLongArray v0 = v;
			CLongArray v1 = b1.v;
			CLongArray v2 = b2.v;
			
			for(int i=0; i<SIZE; i++)
			{
				v0.set(i, v1.get(i) ^ v2.get(i));
			}
		}


		protected void xorWith(Block b1)
		{
			CLongArray v0 = v;
			CLongArray v1 = b1.v;
			
			for(int i=0; i<SIZE; i++)
			{
				v0.xor(i, v1.get(i));
			}
		}


		protected void xorWith(Block b1, Block b2)
		{
			CLongArray v0 = v;
			CLongArray v1 = b1.v;
			CLongArray v2 = b2.v;
			
			for(int i=0; i<SIZE; i++)
			{
				v0.xor(i, v1.get(i) ^ v2.get(i));
			}
		}


		public Block clear()
		{
			v.fill(0);
			return this;
		}
	}
	
	
	//
	

	protected static class Position
	{
		int pass;
		int lane;
		int slice;
	}
}
