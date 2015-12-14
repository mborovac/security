package labosi;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class CustomMessageDigest {
	
	final protected static int MAX_READ = 4000;
	
	public static byte[] digest(byte[] data, byte[] expectedHash, boolean compare) throws IOException, 
		NoSuchAlgorithmException {
		
		MessageDigest sha = MessageDigest.getInstance("SHA-1");
		byte[] digestedValue = sha.digest(data);
		if(!compare) {
			return digestedValue;
		}
		if(compareByteArrays(digestedValue, expectedHash)) {
			System.out.println("Digesting completed. Digest matches decrypted digest.");
		} else {
			System.out.println("Digesting completed. Digest does not match decrypted digest. Digest was: \n" 
					+ HexString.byteArrayToHexString(digestedValue));
			return null;
		}
		return digestedValue;
	}
	
	private static boolean compareByteArrays(byte[] array1, byte[] array2) {
		if(array1.length != array2.length) {
			return false;
		} else {
			for(int i = 0; i < array1.length; i++) {
				if(array1[i] != array2[i]) {
					return false;
				}
			}
			return true;
		}
	}
}
