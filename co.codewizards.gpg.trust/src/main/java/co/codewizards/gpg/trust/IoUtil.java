package co.codewizards.gpg.trust;

import static co.codewizards.gpg.trust.AssertUtil.*;

public class IoUtil {

	private IoUtil() {
	}

	public static byte[] longToBytes(final long value) {
		final byte[] bytes = new byte[8];
		longToBytes(value, bytes, 0);
		return bytes;
	}
	public static void longToBytes(final long value, final byte[] bytes, final int index) {
		assertNotNull("bytes", bytes);
		if (bytes.length - index < 8)
			throw new IllegalArgumentException("bytes.length - index < 8");

		for (int i = 0; i < 8; ++i)
			bytes[index + i] = (byte) (value >>> (8 * (8 - 1 - i)));
	}

	public static long bytesToLong(final byte[] bytes) {
		assertNotNull("bytes", bytes);
		if (bytes.length != 8)
			throw new IllegalArgumentException("bytes.length != 8");

		return bytesToLong(bytes, 0);
	}
	public static long bytesToLong(final byte[] bytes, final int index) {
		assertNotNull("bytes", bytes);
		if (bytes.length - index < 8)
			throw new IllegalArgumentException("bytes.length - index < 8");

		long value = 0;
		for (int i = 0; i < 8; ++i)
			value |= ((long) (bytes[index + i] & 0xff)) << (8 * (8 - 1 - i));

		return value;
	}

	public static byte[] intToBytes(final int value) {
		final byte[] bytes = new byte[4];
		intToBytes(value, bytes, 0);
		return bytes;
	}

	public static void intToBytes(final int value, final byte[] bytes, final int index) {
		assertNotNull("bytes", bytes);
		if (bytes.length - index < 4)
			throw new IllegalArgumentException("bytes.length - index < 4");

		for (int i = 0; i < 4; ++i)
			bytes[index + i] = (byte) (value >>> (8 * (4 - 1 - i)));
	}

	public static int bytesToInt(final byte[] bytes) {
		assertNotNull("bytes", bytes);
		if (bytes.length != 4)
			throw new IllegalArgumentException("bytes.length != 4");

		return bytesToInt(bytes, 0);
	}

	public static int bytesToInt(final byte[] bytes, final int index) {
		assertNotNull("bytes", bytes);
		if (bytes.length - index < 4)
			throw new IllegalArgumentException("bytes.length - index < 4");

		int value = 0;
		for (int i = 0; i < 4; ++i)
			value |= ((long) (bytes[index + i] & 0xff)) << (8 * (4 - 1 - i));

		return value;
	}
}
