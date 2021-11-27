package goryachev.memsafecrypto.bc;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.CCharArray;


/**
 * Standard char[] to byte[] converters for password based derivation algorithms.
 */
public enum PasswordConverter
	implements CharToByteConverter
{
	/**
	 * Do a straight char[] to 8 bit conversion.
	 */
	ASCII
	{
		public String getType()
		{
			return "ASCII";
		}


		public CByteArray convert(CCharArray password)
		{
			return PBEParametersGenerator.PKCS5PasswordToBytes(password);
		}
	},
	/**
	 * Do a char[] conversion by producing UTF-8 data.
	 */
	UTF8
	{
		public String getType()
		{
			return "UTF8";
		}


		public CByteArray convert(CCharArray password)
		{
			return PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password);
		}
	},
	/**
	 * Do char[] to BMP conversion (i.e. 2 bytes per character).
	 */
	PKCS12
	{
		public String getType()
		{
			return "PKCS12";
		}


		public CByteArray convert(CCharArray password)
		{
			return PBEParametersGenerator.PKCS12PasswordToBytes(password);
		}
	};
}
