package co.codewizards.gpg.trust;

public class AssertUtil {

	private AssertUtil() {
	}

	public static final <T> T assertNotNull(final String name, final T object) {
		if (object == null)
			throw new IllegalArgumentException(String.format("%s == null", name));

		return object;
	}
}
