package goryachev.memsafecrypto.bc;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.Crypto;
import goryachev.memsafecrypto.ICryptoZeroable;


/**
 * Parameter class for the HKDFBytesGenerator class.
 */
public class HKDFParameters
	implements DerivationParameters, ICryptoZeroable
{
	private final CByteArray ikm;
	private final boolean skipExpand;
	private final CByteArray salt;
	private final CByteArray info;
	

	private HKDFParameters(CByteArray ikm, boolean skip, CByteArray salt, CByteArray info)
	{
		if(ikm == null)
		{
			throw new IllegalArgumentException("IKM (input keying material) should not be null");
		}

		this.ikm = CByteArray.readOnly(ikm);

		this.skipExpand = skip;

		if(salt == null || salt.length() == 0)
		{
			this.salt = null;
		}
		else
		{
			this.salt = CByteArray.readOnly(salt);
		}

		if(info == null)
		{
			this.info = new CByteArray(0);
		}
		else
		{
			this.info = CByteArray.readOnly(info);
		}
	}


	/**
	 * Generates parameters for HKDF, specifying both the optional salt and
	 * optional info. Step 1: Extract won't be skipped.
	 *
	 * @param ikm  the input keying material or seed
	 * @param salt the salt to use, may be null for a salt for hashLen zeros
	 * @param info the info to use, may be null for an info field of zero bytes
	 */
	public HKDFParameters(CByteArray ikm, CByteArray salt, CByteArray info)
	{
		this(ikm, false, salt, info);
	}


	/**
	 * Factory method that makes the HKDF skip the extract part of the key
	 * derivation function.
	 *
	 * @param ikm  the input keying material or seed, directly used for step 2:
	 *             Expand
	 * @param info the info to use, may be null for an info field of zero bytes
	 * @return HKDFParameters that makes the implementation skip step 1
	 */
	public static HKDFParameters skipExtractParameters(CByteArray ikm, CByteArray info)
	{
		return new HKDFParameters(ikm, true, null, info);
	}


	public static HKDFParameters defaultParameters(CByteArray ikm)
	{
		return new HKDFParameters(ikm, false, null, null);
	}


	/**
	 * Returns the (read-only) input keying material or seed.
	 *
	 * @return the keying material
	 */
	public CByteArray getIKM()
	{
		return ikm;
	}


	/**
	 * Returns if step 1: extract has to be skipped or not
	 *
	 * @return true for skipping, false for no skipping of step 1
	 */
	public boolean skipExtract()
	{
		return skipExpand;
	}


	/**
	 * Returns the (read-only) salt, or null if the salt should be generated as a byte array
	 * of HashLen zeros.
	 *
	 * @return the salt, or null
	 */
	public CByteArray getSalt()
	{
		return salt;
	}


	/**
	 * Returns the (read-only) info field, which may be empty (null is converted to empty).
	 *
	 * @return the info field, never null
	 */
	public CByteArray getInfo()
	{
		return info;
	}


	public void zero()
	{
		Crypto.zero(ikm);
		Crypto.zero(salt);
		Crypto.zero(info);
	}
}
