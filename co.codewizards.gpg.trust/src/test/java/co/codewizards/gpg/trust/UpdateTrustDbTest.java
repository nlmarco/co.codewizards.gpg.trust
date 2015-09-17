package co.codewizards.gpg.trust;

import static co.codewizards.gpg.trust.TrustConst.*;
import static org.assertj.core.api.Assertions.*;
import static org.bouncycastle.openpgp.PGPSignature.*;

import org.junit.Test;

import co.codewizards.gpg.trust.key.PgpKey;

public class UpdateTrustDbTest extends AbstractTrustDbTest {

	@Test
	public void directOnly() throws Exception {
		PgpKey aliceKey = createPgpKey("alice");
		PgpKey bobKey = createPgpKey("bob");
		PgpKey cathrinKey = createPgpKey("cathrin");

		bobKey = signPublicKey(aliceKey, POSITIVE_CERTIFICATION, bobKey);

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

	@Test
	public void oneIndirection() throws Exception {
		PgpKey aliceKey = createPgpKey("alice");
		PgpKey bobKey = createPgpKey("bob");
		PgpKey cathrinKey = createPgpKey("cathrin"); // not signed at all
		PgpKey danielKey = createPgpKey("daniel");
		PgpKey emilKey = createPgpKey("emil");
		PgpKey frankKey = createPgpKey("frank");
		PgpKey georgKey = createPgpKey("georg");
		PgpKey hansKey = createPgpKey("hans");

		bobKey = signPublicKey(aliceKey, POSITIVE_CERTIFICATION, bobKey); // bob <= alice
		danielKey = signPublicKey(bobKey, POSITIVE_CERTIFICATION, danielKey); // daniel <= bob <= alice
		emilKey = signPublicKey(cathrinKey, POSITIVE_CERTIFICATION, emilKey); // emil <= cathrin ||| alice
		frankKey = signPublicKey(aliceKey, POSITIVE_CERTIFICATION, frankKey); // frank <= alice

		georgKey = signPublicKey(frankKey, POSITIVE_CERTIFICATION, georgKey); // georg <= frank <= alice
		hansKey = signPublicKey(bobKey, CASUAL_CERTIFICATION, hansKey); // hans <= bob <= alice

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
				assertThat(trustDb.getValidity(hansKey.getPublicKey())).isEqualTo(TRUST_FULLY); // the signature type (CASUAL) has no effect :-(
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
			assertThat(trustDb.getValidity(hansKey.getPublicKey())).isEqualTo(TRUST_FULLY); // behave like GnuPG!
		}
	}

	@Test
	public void twoIndirections() throws Exception {
		PgpKey aliceKey = createPgpKey("alice");

		PgpKey bobKey = createPgpKey("bob");
		PgpKey cathrinKey = createPgpKey("cathrin");
		PgpKey danielKey = createPgpKey("daniel");
		PgpKey emilKey = createPgpKey("emil");

		PgpKey frankKey = createPgpKey("frank");
		PgpKey georgKey = createPgpKey("georg");
		PgpKey hansKey = createPgpKey("hans");
		PgpKey idaKey = createPgpKey("ida");

		PgpKey johnKey = createPgpKey("john");
//		PgpKey karlKey = createPgpKey("karl", null);

		bobKey = signPublicKey(aliceKey, POSITIVE_CERTIFICATION, bobKey); // bob <= alice
		cathrinKey = signPublicKey(aliceKey, POSITIVE_CERTIFICATION, cathrinKey); // cathrin <= alice
		danielKey = signPublicKey(aliceKey, POSITIVE_CERTIFICATION, danielKey); // daniel <= alice
		emilKey = signPublicKey(aliceKey, POSITIVE_CERTIFICATION, emilKey); // emil <= alice

		frankKey = signPublicKey(bobKey, POSITIVE_CERTIFICATION, frankKey); // frank <= bob <= alice
		georgKey = signPublicKey(cathrinKey, POSITIVE_CERTIFICATION, georgKey); // georg <= cathrin <= alice
		hansKey = signPublicKey(danielKey, POSITIVE_CERTIFICATION, hansKey); // hans <= daniel <= alice
		idaKey = signPublicKey(emilKey, POSITIVE_CERTIFICATION, idaKey); // hans <= emil <= alice

		johnKey = signPublicKey(frankKey, POSITIVE_CERTIFICATION, johnKey); // john <= frank <= bob <= alice

		try (TrustDb trustDb = new TrustDb(trustdbFile, pgpKeyRegistry);) {
			trustDb.setOwnerTrust(aliceKey.getPublicKey(), TRUST_ULTIMATE);

			trustDb.setOwnerTrust(bobKey.getPublicKey(), TRUST_MARGINAL);
			trustDb.setOwnerTrust(cathrinKey.getPublicKey(), TRUST_MARGINAL);
			trustDb.setOwnerTrust(danielKey.getPublicKey(), TRUST_MARGINAL);
			trustDb.setOwnerTrust(emilKey.getPublicKey(), TRUST_MARGINAL);

			trustDb.setOwnerTrust(frankKey.getPublicKey(), TRUST_MARGINAL);
			trustDb.setOwnerTrust(georgKey.getPublicKey(), TRUST_MARGINAL);
			trustDb.setOwnerTrust(hansKey.getPublicKey(), TRUST_MARGINAL);
			trustDb.setOwnerTrust(idaKey.getPublicKey(), TRUST_MARGINAL);
		}

		if (! SKIP_GPG_CHECK_TRUST_DB) {
			runGpgCheckTrustDb();

			try (TrustDb trustDb = new TrustDb(trustdbFile, pgpKeyRegistry);) {
				assertThat(trustDb.getValidity(bobKey.getPublicKey())).isEqualTo(TRUST_FULLY);
				assertThat(trustDb.getValidity(cathrinKey.getPublicKey())).isEqualTo(TRUST_FULLY);
				assertThat(trustDb.getValidity(danielKey.getPublicKey())).isEqualTo(TRUST_FULLY);
				assertThat(trustDb.getValidity(emilKey.getPublicKey())).isEqualTo(TRUST_FULLY);

				assertThat(trustDb.getValidity(frankKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
				assertThat(trustDb.getValidity(georgKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
				assertThat(trustDb.getValidity(hansKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
				assertThat(trustDb.getValidity(idaKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);

				assertThat(trustDb.getValidity(johnKey.getPublicKey())).isEqualTo(TRUST_UNKNOWN);
			}
		}

		try (TrustDb trustDb = new TrustDb(trustdbFile, pgpKeyRegistry);) {
			trustDb.updateTrustDb();

			assertThat(trustDb.getValidity(bobKey.getPublicKey())).isEqualTo(TRUST_FULLY);
			assertThat(trustDb.getValidity(cathrinKey.getPublicKey())).isEqualTo(TRUST_FULLY);
			assertThat(trustDb.getValidity(danielKey.getPublicKey())).isEqualTo(TRUST_FULLY);
			assertThat(trustDb.getValidity(emilKey.getPublicKey())).isEqualTo(TRUST_FULLY);

			assertThat(trustDb.getValidity(frankKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
			assertThat(trustDb.getValidity(georgKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
			assertThat(trustDb.getValidity(hansKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
			assertThat(trustDb.getValidity(idaKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);

			assertThat(trustDb.getValidity(johnKey.getPublicKey())).isEqualTo(TRUST_UNKNOWN);
		}

		frankKey = signPublicKey(cathrinKey, POSITIVE_CERTIFICATION, frankKey); // frank <= bob+cathrin <= alice
		georgKey = signPublicKey(bobKey, POSITIVE_CERTIFICATION, georgKey); // georg <= bob+cathrin <= alice
		hansKey = signPublicKey(emilKey, POSITIVE_CERTIFICATION, hansKey); // hans <= daniel+emil <= alice
		idaKey = signPublicKey(danielKey, POSITIVE_CERTIFICATION, idaKey); // hans <= daniel+emil <= alice

		johnKey = signPublicKey(georgKey, POSITIVE_CERTIFICATION, johnKey); // john <= frank+georg <= bob+cathrin <= alice
		johnKey = signPublicKey(hansKey, POSITIVE_CERTIFICATION, johnKey); // john <= frank+georg+hans <= bob+cathrin+daniel+emil <= alice

		if (! SKIP_GPG_CHECK_TRUST_DB) {
			runGpgCheckTrustDb();

			try (TrustDb trustDb = new TrustDb(trustdbFile, pgpKeyRegistry);) {
				assertThat(trustDb.getValidity(frankKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
				assertThat(trustDb.getValidity(georgKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
				assertThat(trustDb.getValidity(hansKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
				assertThat(trustDb.getValidity(idaKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);

				assertThat(trustDb.getValidity(johnKey.getPublicKey())).isEqualTo(TRUST_UNKNOWN);
			}
		}

		try (TrustDb trustDb = new TrustDb(trustdbFile, pgpKeyRegistry);) {
			trustDb.updateTrustDb();

			assertThat(trustDb.getValidity(frankKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
			assertThat(trustDb.getValidity(georgKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
			assertThat(trustDb.getValidity(hansKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
			assertThat(trustDb.getValidity(idaKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);

			assertThat(trustDb.getValidity(johnKey.getPublicKey())).isEqualTo(TRUST_UNKNOWN);
		}


		frankKey = signPublicKey(emilKey, POSITIVE_CERTIFICATION, frankKey); // frank <= bob+cathrin+emil <= alice
		georgKey = signPublicKey(emilKey, POSITIVE_CERTIFICATION, georgKey); // georg <= bob+cathrin+emil <= alice

		// john <= frank+georg+hans <= bob+cathrin+daniel+emil <= alice

		if (! SKIP_GPG_CHECK_TRUST_DB) {
			runGpgCheckTrustDb();

			try (TrustDb trustDb = new TrustDb(trustdbFile, pgpKeyRegistry);) {
				assertThat(trustDb.getValidity(frankKey.getPublicKey())).isEqualTo(TRUST_FULLY);
				assertThat(trustDb.getValidity(georgKey.getPublicKey())).isEqualTo(TRUST_FULLY);
				assertThat(trustDb.getValidity(hansKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
				assertThat(trustDb.getValidity(idaKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);

				assertThat(trustDb.getValidity(johnKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
			}
		}

		try (TrustDb trustDb = new TrustDb(trustdbFile, pgpKeyRegistry);) {
			trustDb.updateTrustDb();

			assertThat(trustDb.getValidity(frankKey.getPublicKey())).isEqualTo(TRUST_FULLY);
			assertThat(trustDb.getValidity(georgKey.getPublicKey())).isEqualTo(TRUST_FULLY);
			assertThat(trustDb.getValidity(hansKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
			assertThat(trustDb.getValidity(idaKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);

			assertThat(trustDb.getValidity(johnKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);
		}

		hansKey = signPublicKey(cathrinKey, POSITIVE_CERTIFICATION, hansKey); // hans <= cathrin+daniel+emil <= alice

		// UNCHANGED: john <= frank+georg+hans <= bob+cathrin+daniel+emil <= alice
		// only the validity of hans' key changed from MARGINAL to FULLY - and is now taken into account.
		// => now there are 3 marginal signatures for john => it changes from MARGINAL to FULLY, too.

		if (! SKIP_GPG_CHECK_TRUST_DB) {
			runGpgCheckTrustDb();

			try (TrustDb trustDb = new TrustDb(trustdbFile, pgpKeyRegistry);) {
				assertThat(trustDb.getValidity(frankKey.getPublicKey())).isEqualTo(TRUST_FULLY);
				assertThat(trustDb.getValidity(georgKey.getPublicKey())).isEqualTo(TRUST_FULLY);
				assertThat(trustDb.getValidity(hansKey.getPublicKey())).isEqualTo(TRUST_FULLY);
				assertThat(trustDb.getValidity(idaKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);

				assertThat(trustDb.getValidity(johnKey.getPublicKey())).isEqualTo(TRUST_FULLY);
			}
		}

		try (TrustDb trustDb = new TrustDb(trustdbFile, pgpKeyRegistry);) {
			trustDb.updateTrustDb();

			assertThat(trustDb.getValidity(frankKey.getPublicKey())).isEqualTo(TRUST_FULLY);
			assertThat(trustDb.getValidity(georgKey.getPublicKey())).isEqualTo(TRUST_FULLY);
			assertThat(trustDb.getValidity(hansKey.getPublicKey())).isEqualTo(TRUST_FULLY);
			assertThat(trustDb.getValidity(idaKey.getPublicKey())).isEqualTo(TRUST_MARGINAL);

			assertThat(trustDb.getValidity(johnKey.getPublicKey())).isEqualTo(TRUST_FULLY);
		}
	}
}
