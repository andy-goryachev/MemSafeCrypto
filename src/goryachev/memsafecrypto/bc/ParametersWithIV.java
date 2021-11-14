package goryachev.memsafecrypto.bc;
import goryachev.memsafecrypto.ByteArray;


public class ParametersWithIV
	implements CipherParameters
{
	private ByteArray iv;
	private CipherParameters parameters;
	

	public ParametersWithIV(CipherParameters parameters, byte[] iv)
	{
		this(parameters, iv, 0, iv.length);
	}


	public ParametersWithIV(CipherParameters parameters, byte[] iv, int ivOff, int ivLen)
	{
		this.iv = ByteArray.readOnly(iv, ivOff, ivLen);  
		this.parameters = parameters;
	}


	public ByteArray getIV()
	{
		return iv;
	}


	public CipherParameters getParameters()
	{
		return parameters;
	}
}
