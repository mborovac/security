package labosi;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class Pecat {
	
	private static SecretKey secretKey;
	private static char[] finalData;
	private static char[] finalDigest;
	private static String initializationVector;
	private static String modulus;
	private static String publicExponent;
	private static String privateExponent;
	private static String signature;
	
	public static void main(String[] args) throws IOException, InvalidKeyException, 
		NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, 
			InvalidAlgorithmParameterException {
		
		createSeal("./lib/createSeal.txt");
		openSeal("./lib/seal.txt");
	}
	
	public static void createSeal(String file) throws IOException, NoSuchAlgorithmException, 
		InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, 
			InvalidAlgorithmParameterException {
		
		ReadCryptoFile fileSpecs = new ReadCryptoFile(new File(file));
		if(fileSpecs.description == null || fileSpecs.method == null) {
			throw new RuntimeException("Description and method are required properties.");
		}
		
		initializationVector = fileSpecs.initializationVector;
		modulus = fileSpecs.modulus;
		publicExponent = fileSpecs.publicExponent;
		privateExponent = fileSpecs.privateExponent;
		
		BigInteger tempModulus = new BigInteger(HexString.hexToByte(modulus));
		BigInteger tempPrivateExponent = new BigInteger(HexString.hexToByte(privateExponent));
		PrivateKey privKey =  RSA.generateRsaPrivateKey(tempModulus, tempPrivateExponent);
		byte[] tempData = Base64Coder.decode(fileSpecs.data);
		
		// SHA-1 signature
		byte[] digest = CustomMessageDigest.digest(tempData, null, false);
		
		// RSA signature
		byte[] encryptedDigest = RSA.rsaEncrypt(digest, privKey);
		finalDigest = Base64Coder.encode(encryptedDigest);
		
		// AES envelope
		secretKey = AES.generateAESKey();
		byte[] keyBytes = new byte[secretKey.getEncoded().length];
		for(int i = 0; i < secretKey.getEncoded().length; i++) {
			keyBytes[i] = secretKey.getEncoded()[i];
		}
		byte[] encryptedData = AES.encrypt(keyBytes, HexString.hexToByte(initializationVector), tempData);
		finalData = Base64Coder.encode(encryptedData);
		
		// RSA envelope
		BigInteger tempPublicExponent = new BigInteger(HexString.hexToByte(publicExponent));
		PublicKey pbKey = RSA.generateRsaPublicKey(tempModulus, tempPublicExponent);
		byte[] encryptedSecretKey = RSA.rsaEncrypt(keyBytes, pbKey);
		String finalSecretKey = HexString.byteArrayToHexString(encryptedSecretKey);
		writeToFile("./lib/seal.txt", finalData, finalSecretKey.toCharArray(), finalDigest);
	}
	
	public static void openSeal(String file) throws IOException, InvalidKeyException, IllegalBlockSizeException, 
		BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		
		ReadCryptoFile fileSpecs = new ReadCryptoFile(new File(file));
		if(fileSpecs.description == null || fileSpecs.method == null) {
			throw new RuntimeException("Description and method are required properties.");
		}
		
		initializationVector = fileSpecs.initializationVector;
		modulus = fileSpecs.modulus;
		publicExponent = fileSpecs.publicExponent;
		privateExponent = fileSpecs.privateExponent;
		signature = fileSpecs.signature;
		
		
		BigInteger tempModulus = new BigInteger(HexString.hexToByte(modulus));
		BigInteger tempPublickExponent = new BigInteger(HexString.hexToByte(publicExponent));
		
		// RSA envelope
		BigInteger tempPrivateExponent = new BigInteger(HexString.hexToByte(privateExponent));
		PrivateKey privKey =  RSA.generateRsaPrivateKey(tempModulus, tempPrivateExponent);
		byte[] encryptedSecretKey = HexString.hexToByte(fileSpecs.envelopeCryptKey);
		byte[] decryptedSecretKey = RSA.rsaDecrypt(encryptedSecretKey, privKey);
		
		// AES envelope
		String envelopeData = fileSpecs.envelopeData;
		byte[] decodedEnvelopeData = Base64Coder.decode(envelopeData);
		byte[] decryptedOriginalData = AES.decrypt(decryptedSecretKey, HexString.hexToByte(initializationVector), 
				decodedEnvelopeData);
		
		// RSA signature
		PublicKey pubKey =  RSA.generateRsaPublicKey(tempModulus, tempPublickExponent);
		byte[] decodedSignature = Base64Coder.decode(signature);
		byte[] decryptedSignature = RSA.rsaDecrypt(decodedSignature, pubKey);
		byte[] originalData = decryptedOriginalData;
		
		// SHA-1 signature
		byte[] digestReturnValue = CustomMessageDigest.digest(originalData, decryptedSignature, true);
		if(digestReturnValue == null) {
			System.out.println("Exiting...");
			System.exit(-1);
		}
		
		System.out.println("Decrypted data:");
		System.out.print(new String(decryptedOriginalData, "UTF-8"));
		System.out.println("Original data:");
		System.out.println(new String(originalData, "UTF-8"));
	}
	
	public static void writeToFile(String fileName, char[] envelopeData, char[] envelopeCryptKey, char[] digest) 
			throws IOException {
		
		BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
		          new FileOutputStream(fileName), StandardCharsets.UTF_8));
		writer.write("---BEGIN OS2 CRYPTO DATA---\n");
		writer.write("Description:\n");
		writer.write("    Seal\n\n");
		writer.write("Method:\n");
		writer.write("    AES/RSA/SHA-1\n\n");
		writer.write("Initialization vector:\n");
		writer.write(createAttributeValueString(initializationVector.toCharArray()) + "\n");
//		writer.write("Data:\n");
//		writer.write(createAttributeValueString(data.toCharArray()) + "\n");
		writer.write("Modulus:\n");
		writer.write(createAttributeValueString(modulus.toCharArray()) + "\n");
		writer.write("Public exponent:\n");
		writer.write(createAttributeValueString(publicExponent.toCharArray()) + "\n");
		writer.write("Private exponent:\n");
		writer.write(createAttributeValueString(privateExponent.toCharArray()) + "\n");
		writer.write("Signature:\n");
		writer.write(createAttributeValueString(digest) + "\n");
		writer.write("Envelope data:\n");
		writer.write(createAttributeValueString(envelopeData) + "\n");
		writer.write("Envelope crypt key:\n");
		writer.write(createAttributeValueString(envelopeCryptKey) + "\n");
		writer.write("---END OS2 CRYPTO DATA---");
		writer.flush();
		writer.close();
	}
	
	private static String createAttributeValueString(char[] attributeValue) {
		StringBuilder sb = new StringBuilder();
		String leadingSpace = "    ";
		int current = 0;
		while(current < attributeValue.length) {
			sb.append(leadingSpace);
			if(attributeValue.length - current < 60) {
				for(int i = 0; i < attributeValue.length - current; i++) {
					sb.append(attributeValue[i + current]);
				}
				current += attributeValue.length;
				sb.append("\n");
			} else {
				for(int i = 0; i < 60; i++) {
					sb.append(attributeValue[i + current]);
				}
				current += 60;
				sb.append("\n");
			}
		}
		return sb.toString();
	}
}
