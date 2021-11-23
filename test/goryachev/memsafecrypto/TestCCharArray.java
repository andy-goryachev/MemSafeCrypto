// Copyright © 2021 Andy Goryachev <andy@goryachev.com>
package goryachev.memsafecrypto;
import goryachev.common.test.TF;
import goryachev.common.test.Test;


/**
 * Tests CCharArray.
 */
public class TestCCharArray
{
	public static void main(String[] args)
	{
		TF.run();
	}
	
	
	@Test
	public void testZero()
	{
		new CCharArray(0);
	}
	
	
	@Test
	public void testAdd()
	{
		ta("a", "b", "ab");
		ta("a", "bc", "abc");
		ta("", "a", "a");
		ta("", "", "");
	}
	
	
	@Test
	public void testDelete()
	{
		td("abc", "ab");
		td("ab", "a");
		td("a", "");
		td("", "");
	}
	
	
	protected void ta(String text, String add, String expected)
	{
		CCharArray a = new CCharArray(text.toCharArray());
		CCharArray r = a.append(add.toCharArray());
		char[] res = r.toCharArray();
		TF.eq(res, expected.toCharArray()); 
	}
	
	
	protected void td(String text, String expected)
	{
		CCharArray a = new CCharArray(text.toCharArray());
		CCharArray r = a.deleteLastChar();
		char[] res = r.toCharArray();
		TF.eq(res, expected.toCharArray()); 
	}
}
