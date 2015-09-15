package co.codewizards.gpg.trust;

import static co.codewizards.gpg.trust.TrustConst.*;
import static org.assertj.core.api.Assertions.*;

import org.junit.Test;

import co.codewizards.gpg.trust.key.PgpKey;

public class DirectOnlyTest extends AbstractTrustDbTest {

	@Test
	public void directOnly() throws Exception {
		PgpKey aliceKey = createPgpKey("alice", null);
		PgpKey bobKey = createPgpKey("bob", null);
		PgpKey cathrinKey = createPgpKey("cathrin", null);

		bobKey = signPublicKey(aliceKey, null, bobKey);

		try (TrustDb trustDb = new TrustDb(trustdbFile, pgpKeyRegistry);) {
			trustDb.setOwnerTrust(aliceKey.getPublicKey(), TRUST_ULTIMATE);
		}

		if (! SKIP_GPG_CHECK_TRUST_DB) {
			runGpgCheckTrustDb();

			try (TrustDb trustDb = new TrustDb(trustdbFile, pgpKeyRegistry);) {
				assertThat(trustDb.getValidity(aliceKey.getPublicKey())).isEqualTo(TRUST_ULTIMATE);
				assertThat(trustDb.getValidity(bobKey.getPublicKey())).isEqualTo(TRUST_FULLY);
				assertThat(trustDb.getValidity(cathrinKey.getPublicKey())).isEqualTo(TRUST_UNKNOWN);
			}
		}

		try (TrustDb trustDb = new TrustDb(trustdbFile, pgpKeyRegistry);) {
			trustDb.updateTrustDb();
			assertThat(trustDb.getValidity(aliceKey.getPublicKey())).isEqualTo(TRUST_ULTIMATE);
			assertThat(trustDb.getValidity(bobKey.getPublicKey())).isEqualTo(TRUST_FULLY);
			assertThat(trustDb.getValidity(cathrinKey.getPublicKey())).isEqualTo(TRUST_UNKNOWN);
		}
	}

}
