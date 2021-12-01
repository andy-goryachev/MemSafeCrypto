package goryachev.memsafecrypto.bc;
import goryachev.memsafecrypto.CByteArray;
import goryachev.memsafecrypto.Crypto;
import goryachev.memsafecrypto.ICryptoZeroable;


public class ParametersWithIV
	implements CipherParameters, ICryptoZeroable
{
	private CByteArray iv;
	private CipherParameters parameters;
	

	public ParametersWithIV(CipherParameters parameters, byte[] iv)
	{
		this(parameters, iv, 0, iv.length);
	}


	public ParametersWithIV(CipherParameters parameters, byte[] iv, int ivOff, int ivLen)
	{
		this.iv = CByteArray.readOnly(iv, ivOff, ivLen);
		this.parameters = parameters;
	}


	public ParametersWithIV(CipherParameters parameters, CByteArray iv)
	{
		this(parameters, iv, 0, iv.length());
	}


	public ParametersWithIV(CipherParameters parameters, CByteArray iv, int ivOff, int ivLen)
	{
		this.iv = CByteArray.readOnly(iv, ivOff, ivLen);
		this.parameters = parameters;
	}


	public CByteArray getIV()
	{
		return iv;
	}


	public CipherParameters getParameters()
	{
		return parameters;
	}


	public void zero()
	{
		Crypto.zero(parameters);
		Crypto.zero(iv);
	}
}
