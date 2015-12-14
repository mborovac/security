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

public class Omotnica {
	
	private static SecretKey secretKey;
	private static char[] finalData;
	private static String initializationVector;
	private static String modulus;
	private static String publicExponent;
	private static String privateExponent;
	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException, 
		NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		
		createEnvelope("./lib/createEnvelope.txt");
		openEnvelope("./lib/envelope.txt");
	}
	
	public static void createEnvelope(String file) throws IOException, NoSuchAlgorithmException, 
		InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, 
			BadPaddingException {
		
		ReadCryptoFile fileSpecs = new ReadCryptoFile(new File(file));
		if(fileSpecs.description == null || fileSpecs.method == null) {
			throw new RuntimeException("Description and method are required properties.");
		}
		if(fileSpecs.data == null) {
			throw new RuntimeException("Data can not be null!");
		}
		if(fileSpecs.initializationVector == null) {
			throw new RuntimeException("Initialization vector can not be null!");
		}
		if(fileSpecs.publicExponent == null) {
			throw new RuntimeException("Public exponent can not be null!");
		}
		if(fileSpecs.modulus == null) {
			throw new RuntimeException("Modulus can not be null!");
		}
		
		initializationVector = fileSpecs.initializationVector;
		modulus = fileSpecs.modulus;
		publicExponent = fileSpecs.publicExponent;
		privateExponent = fileSpecs.privateExponent;
		
		// AES
		secretKey = AES.generateAESKey();
		byte[] keyBytes = new byte[secretKey.getEncoded().length];
		for(int i = 0; i < secretKey.getEncoded().length; i++) {
			keyBytes[i] = secretKey.getEncoded()[i];
		}
		byte[] tempData = Base64Coder.decode(fileSpecs.data);
		byte[] encryptedData = AES.encrypt(keyBytes, HexString.hexToByte(initializationVector), tempData);
		finalData = Base64Coder.encode(encryptedData);
		
		// RSA
		BigInteger tempModulus = new BigInteger(HexString.hexToByte(modulus));
		BigInteger tempPublicExponent = new BigInteger(HexString.hexToByte(publicExponent));
		PublicKey pbKey = RSA.generateRsaPublicKey(tempModulus, tempPublicExponent);
		byte[] encryptedSecretKey = RSA.rsaEncrypt(keyBytes, pbKey);
		String finalSecretKey = HexString.byteArrayToHexString(encryptedSecretKey);
		writeToFile("./lib/envelope.txt", finalData, finalSecretKey.toCharArray());
	}
	
	public static void openEnvelope(String file) throws IOException, InvalidKeyException, IllegalBlockSizeException, 
		BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		
		ReadCryptoFile fileSpecs = new ReadCryptoFile(new File(file));
		if(fileSpecs.description == null || fileSpecs.method == null) {
			throw new RuntimeException("Description and method are required properties.");
		}
		if(fileSpecs.envelopeData == null) {
			throw new RuntimeException("Data can not be null!");
		}
		if(fileSpecs.initializationVector == null) {
			throw new RuntimeException("Initialization vector can not be null!");
		}
//		if(fileSpecs.publicExponent == null) {
//			throw new RuntimeException("Public exponent can not be null!");
//		}
		if(fileSpecs.modulus == null) {
			throw new RuntimeException("Modulus can not be null!");
		}
		
		initializationVector = fileSpecs.initializationVector;
		modulus = fileSpecs.modulus;
//		publicExponent = fileSpecs.publicExponent;
		privateExponent = fileSpecs.privateExponent;
		
		// RSA
		BigInteger tempModulus = new BigInteger(HexString.hexToByte(modulus));
		BigInteger tempPrivateExponent = new BigInteger(HexString.hexToByte(privateExponent));
		PrivateKey privKey =  RSA.generateRsaPrivateKey(tempModulus, tempPrivateExponent);
		byte[] encryptedSecretKey = HexString.hexToByte(fileSpecs.envelopeCryptKey);
		byte[] decryptedSecretKey = RSA.rsaDecrypt(encryptedSecretKey, privKey);
		
		
		// AES
		byte[] data = Base64Coder.decode(fileSpecs.envelopeData);
		byte[] originalData = AES.decrypt(decryptedSecretKey, HexString.hexToByte(initializationVector), data);
		System.out.println("Original data:");
		System.out.println(new String(originalData, "UTF-8"));
	}
	
	public static void writeToFile(String fileName, char[] envelopeData, char[] envelopeCryptKey) throws IOException {
		BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
		          new FileOutputStream(fileName), StandardCharsets.UTF_8));
		writer.write("---BEGIN OS2 CRYPTO DATA---\n");
		writer.write("Description:\n");
		writer.write("    Envelope\n\n");
		writer.write("Method:\n");
		writer.write("    AES/RSA\n\n");
		writer.write("Initialization vector:\n");
		writer.write(createAttributeValueString(initializationVector.toCharArray()) + "\n");
		writer.write("Modulus:\n");
		writer.write(createAttributeValueString(modulus.toCharArray()) + "\n");
//		writer.write("Public exponent:\n");
//		writer.write(createAttributeValueString(publicExponent.toCharArray()) + "\n");
		writer.write("Private exponent:\n");
		writer.write(createAttributeValueString(privateExponent.toCharArray()) + "\n");
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
