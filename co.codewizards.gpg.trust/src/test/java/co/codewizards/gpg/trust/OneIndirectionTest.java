package co.codewizards.gpg.trust;

import static co.codewizards.gpg.trust.TrustConst.*;
import static org.assertj.core.api.Assertions.*;

import org.junit.Test;

import co.codewizards.gpg.trust.key.PgpKey;

public class OneIndirectionTest extends AbstractTrustDbTest {

	@Test
	public void oneIndirectionWithFullyTrustedOwnerOnly() throws Exception {
		PgpKey aliceKey = createPgpKey("alice", null);
		PgpKey bobKey = createPgpKey("bob", null);
		PgpKey cathrinKey = createPgpKey("cathrin", null); // not signed at all
		PgpKey danielKey = createPgpKey("daniel", null);
		PgpKey emilKey = createPgpKey("emil", null);
		PgpKey frankKey = createPgpKey("frank", null);
		PgpKey georgKey = createPgpKey("georg", null);

		bobKey = signPublicKey(aliceKey, null, bobKey);
		danielKey = signPublicKey(bobKey, null, danielKey);
		emilKey = signPublicKey(cathrinKey, null, emilKey);
		frankKey = signPublicKey(aliceKey, null, frankKey);
		georgKey = signPublicKey(frankKey, null, georgKey);

		try (TrustDb trustDb = new TrustDb(trustdbFile, pgpKeyRegistry);) {
			trustDb.setOwnerTrust(aliceKey.getPublicKey(), TRUST_ULTIMATE);

			trustDb.setOwnerTrust(bobKey.getPublicKey(), TRUST_FULLY);
			trustDb.setOwnerTrust(cathrinKey.getPublicKey(), TRUST_FULLY);
			trustDb.setOwnerTrust(frankKey.getPublicKey(), TRUST_MARGINAL);
		}

		if (! SKIP_GPG_CHECK_TRUST_DB) {
			runGpgCheckTrustDb();

			try (TrustDb trustDb = new TrustDb(trustdbFile, pgpKeyRegistry);) {
				assertThat(trustDb.getValidity(aliceKey.getPublicKey())).isEqualTo(TRUST_ULTIMATE);
				assertThat(trustDb.getValidity(bobKey.getPublicKey())).isEqualTo(TRUST_FULLY);
				assertThat(trustDb.getValidity(cathrinKey.getPublicKey())).isEqualTo(TRUST_UNKNOWN);
				assertThat(trustDb.getValidity(danielKey.getPublicKey())).isEqualTo(TRUST_FULLY);
				assertThat(trustDb.getValidity(frankKey.getPublicKey())).isEqualTo(TRUST_FULLY);
				assertThat(trustDb.getValidity(georgKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
			}
		}

		try (TrustDb trustDb = new TrustDb(trustdbFile, pgpKeyRegistry);) {
			trustDb.updateTrustDb();
			assertThat(trustDb.getValidity(aliceKey.getPublicKey())).isEqualTo(TRUST_ULTIMATE);
			assertThat(trustDb.getValidity(bobKey.getPublicKey())).isEqualTo(TRUST_FULLY);
			assertThat(trustDb.getValidity(cathrinKey.getPublicKey())).isEqualTo(TRUST_UNKNOWN);
			assertThat(trustDb.getValidity(danielKey.getPublicKey())).isEqualTo(TRUST_FULLY);
			assertThat(trustDb.getValidity(frankKey.getPublicKey())).isEqualTo(TRUST_FULLY);
			assertThat(trustDb.getValidity(georgKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
		}
	}

}
