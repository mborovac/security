package labosi;

public class HexString {
	
	public static String byteArrayToHexString(byte[] bytes) {
		StringBuffer buffer = new StringBuffer();
		for(int i=0; i<bytes.length; i++) {
			if(((int)bytes[i] & 0xff) < 0x10) {
				buffer.append("0");
			}
			buffer.append(Long.toString((int) bytes[i] & 0xff, 16));
		}
		return buffer.toString();
	}
	  
	public static byte[] hexToByte(String hexText) {
		if((hexText.length()%2) == 1) {
			throw new IllegalArgumentException("Given string is not hex-encoded.");
		}
		int textLength = hexText.length();
		byte[] byteArray = new byte[textLength / 2];
		for (int i = 0; i < textLength; i += 2) {
			byteArray[i / 2] = (byte) ((Character.digit(hexText.charAt(i), 16) << 4)
					+ Character.digit(hexText.charAt(i+1), 16));
		}
		return byteArray;
	}
}
