package labosi;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;

public class ReadCryptoFile {
	
	public String description;
	public String fileName;
	public String method;
	public String keyLength;
	public String secretKey;
	public String initializationVector;
	public String modulus;
	public String publicExponent;
	public String privateExponent;
	public String signature;
	public String data;
	public String envelopeData;
	public String envelopeCryptKey;
	
	public ReadCryptoFile(File file) throws IOException {
		BufferedReader br = new BufferedReader(
			new InputStreamReader(new FileInputStream(file), "UTF-8"));
		String line = br.readLine();
		while(!line.matches("---BEGIN OS2 CRYPTO DATA---")) {
			line = br.readLine();
		}
		line = br.readLine();
		while(true) {
			while(line.isEmpty()) {
				line = br.readLine();
			}
			if(line.matches("---END OS2 CRYPTO DATA---")) {
				break;
			}
			if(line.matches("Description:[\\s]*")) {
				description = readProperty(line, br);
				line = br.readLine();
			}
			if(line.matches("File name:[\\s]*")) {
				fileName = readProperty(line, br);
				line = br.readLine();
			}
			if(line.matches("Method:[\\s]*")) {
				method = readProperty(line, br);
				line = br.readLine();
			}
			if(line.matches("Key length:[\\s]*")) {
				keyLength = readProperty(line, br);
				line = br.readLine();
			}
			if(line.matches("Secret key:[\\s]*")) {
				secretKey = readProperty(line, br);
				line = br.readLine();
			}
			if(line.matches("Initialization vector:[\\s]*")) {
				initializationVector = readProperty(line, br);
				line = br.readLine();
			}
			if(line.matches("Modulus:[\\s]*")) {
				modulus = readProperty(line, br);
				line = br.readLine();
			}
			if(line.matches("Public exponent:[\\s]*")) {
				publicExponent = readProperty(line, br);
				line = br.readLine();
			}
			if(line.matches("Private exponent:[\\s]*")) {
				privateExponent = readProperty(line, br);
				line = br.readLine();
			}
			if(line.matches("Signature:[\\s]*")) {
				signature = readProperty(line, br);
				line = br.readLine();
			}
			if(line.matches("Data:[\\s]*")) {
				data = readProperty(line, br);
				line = br.readLine();
			}
			if(line.matches("Envelope data:[\\s]*")) {
				envelopeData = readProperty(line, br);
				line = br.readLine();
			}
			if(line.matches("Envelope crypt key:[\\s]*")) {
				envelopeCryptKey = readProperty(line, br);
				line = br.readLine();
			}
		}
	}
	
	private String readProperty(String line, BufferedReader br) throws IOException {
		line = br.readLine();
		while(line.isEmpty()) {
			line = br.readLine();
		}
		if(!line.startsWith("    ")) {
			throw new RuntimeException("Badly formed file!");
		}
		line = line.substring(4);
		String property = line;
		while(line.length() == 60) {
			line = br.readLine();
			if(!line.isEmpty() && line.startsWith("    ")) {
				line = line.substring(4);
				property += line;
			} else {
				return property;
			}
		}
		return property;
	}
}
