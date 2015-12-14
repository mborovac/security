package labosi;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSA {
	
	/**
	 * Generates an RSA key pair
	 * 
	 * @param keySize key length
	 * @param publicExponent
	 * @return returns a key pair
	 */
	public static KeyPair generateRsaKeyPair(int keySize, BigInteger publicExponent) {
		
		KeyPair keys = null;
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(keySize, publicExponent);
			keyGen.initialize(spec);
			keys = keyGen.generateKeyPair();
		}
		catch(Exception e) {
	    //  Logger.e(e.toString());
	    }
		return keys;
	}

	/**
	 * Generates an RSA public key with given modulus and public exponent
	 * 
	 * @param modulus (must be positive)
	 * @param publicExponent
	 * @return returns public key
	 */
	public static PublicKey generateRsaPublicKey(BigInteger modulus, BigInteger publicExponent) {
		try {
			return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
		}
		catch(Exception e) {
	    //  Logger.e(e.toString());
		}
		return null;
	}
	  
	/**
	 * Generates an RSA private key with given modulus and private exponent
	 * 
	 * @param modulus (must be positive)
	 * @param privateExponent
	 * @return returns private key
	 */
	public static PrivateKey generateRsaPrivateKey(BigInteger modulus, BigInteger privateExponent) {
		try {
			return KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateKeySpec(modulus, privateExponent));
		}
		catch(Exception e) {
	    //  Logger.e(e.toString());
		}
		return null;
	}
	  
	/**
	 * RSA encrypt function (RSA / ECB / PKCS1-Padding)
	 * 
	 * @param original byte array to be encrypted
	 * @param key encryption key
	 * @return returns an encrypted byte array
	 */
	public static byte[] rsaEncrypt(byte[] original, Key key) throws IllegalBlockSizeException, 
		BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		  
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(original);
	}
	  
	/**
	 * RSA decryption function (RSA / ECB / PKCS1-Padding)
	 * 
	 * @param encrypted encrypted byte array
	 * @param key decryption key
	 * @return returns a decrypted byte array
	 */
	public static byte[] rsaDecrypt(byte[] encrypted, Key key) throws IllegalBlockSizeException, 
		BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(encrypted);
	}
}
