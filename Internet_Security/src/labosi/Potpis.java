package labosi;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Potpis {
	
	private static char[] finalData;
	private static String modulus;
	private static String publicExponent;
	private static String privateExponent;
	private static String signature;
	private static String data;
	
	public static void main(String[] args) throws IOException, InvalidKeyException, 
			IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		
		createSignature("./lib/createSignature.txt");
		checkSignature("./lib/signature.txt");
	}
	
	public static void createSignature(String file) throws IOException, InvalidKeyException, 
			IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		
		ReadCryptoFile fileSpecs = new ReadCryptoFile(new File(file));
		if(fileSpecs.description == null || fileSpecs.method == null) {
			throw new RuntimeException("Description and method are required properties.");
		}
		
		modulus = fileSpecs.modulus;
		publicExponent = fileSpecs.publicExponent;
		privateExponent = fileSpecs.privateExponent;
		data = fileSpecs.data;
		
		
		BigInteger tempModulus = new BigInteger(HexString.hexToByte(modulus));
		BigInteger tempPrivateExponent = new BigInteger(HexString.hexToByte(privateExponent));
		PrivateKey privKey =  RSA.generateRsaPrivateKey(tempModulus, tempPrivateExponent);
		byte[] tempData = Base64Coder.decode(fileSpecs.data);
		
		byte[] digest = CustomMessageDigest.digest(tempData, null, false);
		
		byte[] encryptedData = RSA.rsaEncrypt(digest, privKey);
		finalData = Base64Coder.encode(encryptedData);
		writeToFile("./lib/signature.txt", finalData);
	}
	
	public static void checkSignature(String file) throws IOException, InvalidKeyException, 
		IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
	
		ReadCryptoFile fileSpecs = new ReadCryptoFile(new File(file));
		if(fileSpecs.description == null || fileSpecs.method == null) {
			throw new RuntimeException("Description and method are required properties.");
		}
		
		modulus = fileSpecs.modulus;
		publicExponent = fileSpecs.publicExponent;
		privateExponent = fileSpecs.privateExponent;
		signature = fileSpecs.signature;
		data = fileSpecs.data;
		
		BigInteger tempModulus = new BigInteger(HexString.hexToByte(modulus));
		BigInteger tempPublickExponent = new BigInteger(HexString.hexToByte(publicExponent));
		PublicKey pubKey =  RSA.generateRsaPublicKey(tempModulus, tempPublickExponent);
		byte[] decodedSignature = Base64Coder.decode(signature);
		byte[] decryptedData = RSA.rsaDecrypt(decodedSignature, pubKey);
		byte[] originalData = Base64Coder.decode(fileSpecs.data);
		
		CustomMessageDigest.digest(originalData, decryptedData, true);
	}
	
	public static void writeToFile(String fileName, char[] digest) throws IOException {
		BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
		          new FileOutputStream(fileName), StandardCharsets.UTF_8));
		writer.write("---BEGIN OS2 CRYPTO DATA---\n");
		writer.write("Description:\n");
		writer.write("    Signature\n\n");
		writer.write("Method:\n");
		writer.write("    SHA-1/RSA\n\n");
		writer.write("Data:\n");
		writer.write(createAttributeValueString(data.toCharArray()) + "\n");
		writer.write("Modulus:\n");
		writer.write(createAttributeValueString(modulus.toCharArray()) + "\n");
		writer.write("Public exponent:\n");
		writer.write(createAttributeValueString(publicExponent.toCharArray()) + "\n");
		writer.write("Private exponent:\n");
		writer.write(createAttributeValueString(privateExponent.toCharArray()) + "\n");
		writer.write("Signature:\n");
		writer.write(createAttributeValueString(digest) + "\n");
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

