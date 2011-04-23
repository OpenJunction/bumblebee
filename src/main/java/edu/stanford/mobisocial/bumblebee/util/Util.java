package edu.stanford.mobisocial.bumblebee.util;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Util {

    /**
	 * Copies a stream.
	 */
	public static void copy(InputStream is, OutputStream os) throws IOException {
		int i;
		byte[] b = new byte[1024];
		while((i=is.read(b))!=-1) {
			os.write(b, 0, i);
		}
	}

    /**
     * Return true if the byte ranges are identical.
     */
	public static final boolean bytesEqual(final byte[] b1, final int j, final byte[] b2,  final int k, final int len){
        for(int i = 0; i < len; i++){
            if(b1[i + j] != b2[i + k]) return false;
        }
        return true;
	}

	private static String convertToHex(byte[] data) {
		StringBuffer buf = new StringBuffer();

		for (int i = 0; i < data.length; i++) {
			int halfbyte = (data[i] >>> 4) & 0x0F;
			int two_halfs = 0;

			do {
				if ((0 <= halfbyte) && (halfbyte <= 9)) {
					buf.append((char) ('0' + halfbyte));
				} else {
					buf.append((char) ('a' + (halfbyte - 10)));
				}

				halfbyte = data[i] & 0x0F;
			} while (two_halfs++ < 1);
		}

		return buf.toString();
	}

	public static String SHA1(byte[] input) throws NoSuchAlgorithmException,
                                                   UnsupportedEncodingException {
		MessageDigest md;
		md = MessageDigest.getInstance("SHA-1");

		byte[] sha1hash = new byte[40];
		md.update(input, 0, input.length);
		sha1hash = md.digest();

		return convertToHex(sha1hash);
	}
}
