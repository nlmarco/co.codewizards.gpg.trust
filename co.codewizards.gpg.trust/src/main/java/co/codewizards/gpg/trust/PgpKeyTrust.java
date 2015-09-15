package co.codewizards.gpg.trust;

import static co.codewizards.gpg.trust.Util.*;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import co.codewizards.gpg.trust.key.PgpKey;
import co.codewizards.gpg.trust.key.PgpKeyFingerprint;
import co.codewizards.gpg.trust.key.PgpUserId;
import co.codewizards.gpg.trust.key.UserIdNameHash;

public class PgpKeyTrust {

	private final PgpKey pgpKey;
	private final Map<UserIdNameHash, PgpUserIdTrust> nameHash2UserIdTrust = new HashMap<>();

	public PgpKeyTrust(final PgpKey pgpKey) {
		this.pgpKey = assertNotNull("pgpKey", pgpKey);
	}

	public PgpKey getPgpKey() {
		return pgpKey;
	}

	public PgpKeyFingerprint getPgpKeyFingerprint() {
		return pgpKey.getPgpKeyFingerprint();
	}

	public PgpUserIdTrust getPgpUserIdTrust(final PgpUserId pgpUserId) {
		assertNotNull("pgpUserId", pgpUserId);
		PgpUserIdTrust pgpUserIdTrust = nameHash2UserIdTrust.get(pgpUserId.getNameHash());
		if (pgpUserIdTrust == null) {
			pgpUserIdTrust = new PgpUserIdTrust(this, pgpUserId);
			nameHash2UserIdTrust.put(pgpUserId.getNameHash(), pgpUserIdTrust);
		}
		return pgpUserIdTrust;
	}

	public Collection<PgpUserIdTrust> getPgpUserIdTrusts() {
		return Collections.unmodifiableCollection(nameHash2UserIdTrust.values());
	}
}
