package co.codewizards.gpg.trust;

public class Config {

	private static final Config instance = new Config();

	protected Config() {
	}

	public static Config getInstance() {
		return instance;
	}

	public short getMarginalsNeeded() {
		return 3;
	}

	public short getCompletesNeeded() {
		return 1;
	}

	public short getMaxCertDepth() {
		return 5;
	}

	public short getTrustModel() {
		return 1; // This must never be anything else! We support only TM_PGP = 1!!!
	}

	public short getMinCertLevel() {
		return 2;
	}
}
