package co.codewizards.gpg.trust;

import static co.codewizards.gpg.trust.Util.*;
import co.codewizards.gpg.trust.key.PgpUserId;

public class PgpUserIdTrust {

	private final PgpKeyTrust pgpKeyTrust;
	private final PgpUserId pgpUserId;

	private int validity, ultimateCount, fullCount, marginalCount;

	public PgpUserIdTrust(final PgpKeyTrust pgpKeyTrust, final PgpUserId pgpUserId) {
		this.pgpKeyTrust = assertNotNull("pgpKeyTrust", pgpKeyTrust);
		this.pgpUserId = assertNotNull("pgpUserId", pgpUserId);
	}

	public PgpKeyTrust getPgpKeyTrust() {
		return pgpKeyTrust;
	}

	public PgpUserId getPgpUserId() {
		return pgpUserId;
	}

	public int getValidity() {
		return validity;
	}

	public void setValidity(int validity) {
		this.validity = validity;
	}

	public int getUltimateCount() {
		return ultimateCount;
	}
	public void setUltimateCount(int ultimateCount) {
		this.ultimateCount = ultimateCount;
	}
	public void incUltimateCount() {
		++ultimateCount;
	}

	public int getFullCount() {
		return fullCount;
	}
	public void setFullCount(int fullCount) {
		this.fullCount = fullCount;
	}
	public void incFullCount() {
		++fullCount;
	}

	public int getMarginalCount() {
		return marginalCount;
	}
	public void setMarginalCount(int marginalCount) {
		this.marginalCount = marginalCount;
	}
	public void incMarginalCount() {
		++marginalCount;
	}
}
