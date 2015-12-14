package labosi;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES {
	
	public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		return keyGen.generateKey();
	}
	
	public static byte[] encrypt(byte[] key, byte[] iv, byte[] data) throws IOException, InvalidKeyException, 
			InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, 
				IllegalBlockSizeException, BadPaddingException {
		
		SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
		AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, paramSpec);
		return cipher.doFinal(data);
	}
	
	public static byte[] decrypt(byte[] key, byte[] iv, byte[] data) throws IOException, NoSuchAlgorithmException, 
			NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, 
				IllegalBlockSizeException, BadPaddingException {
		
		SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
		AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, keySpec, paramSpec);
		return cipher.doFinal(data);
	}
}
