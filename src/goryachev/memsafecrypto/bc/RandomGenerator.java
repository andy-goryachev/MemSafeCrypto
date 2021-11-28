package goryachev.memsafecrypto.bc;
import goryachev.memsafecrypto.CByteArray;


/**
 * Generic interface for objects generating random bytes.
 */
public interface RandomGenerator
{
	/**
	 * Add more seed material to the generator.
	 *
	 * @param seed a byte array to be mixed into the generator's state.
	 */
	public void addSeedMaterial(byte[] seed);


	/**
	 * Add more seed material to the generator.
	 *
	 * @param seed a long value to be mixed into the generator's state.
	 */
	public void addSeedMaterial(long seed);


	/**
	 * Fill bytes with random values.
	 *
	 * @param bytes byte array to be filled.
	 */
	public void nextBytes(byte[] bytes);


	/**
	 * Fill part of bytes with random values.
	 *
	 * @param bytes byte array to be filled.
	 * @param start index to start filling at.
	 * @param len length of segment to fill.
	 */
	public void nextBytes(byte[] bytes, int start, int len);
	
	
	/**
	 * Fill bytes with random values.
	 *
	 * @param bytes byte array to be filled.
	 */
	public void nextBytes(CByteArray bytes);


	/**
	 * Fill part of bytes with random values.
	 *
	 * @param bytes byte array to be filled.
	 * @param start index to start filling at.
	 * @param len length of segment to fill.
	 */
	public void nextBytes(CByteArray bytes, int start, int len);
}
