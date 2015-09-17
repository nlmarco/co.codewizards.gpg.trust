package co.codewizards.gpg.trust;

import static org.assertj.core.api.Assertions.*;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.junit.Ignore;
import org.junit.Test;

import co.codewizards.gpg.trust.TrustRecord.Trust;
import co.codewizards.gpg.trust.key.PgpKeyRegistry;

@Ignore("This test is for playing around while developing - it's not a regular test!")
public class TrustDbProductiveFileTest {

	@Test
	public void readMyProductiveTrustDb() throws Exception {
		String userHome = System.getProperty("user.home");
		File gnuPgHome = new File(userHome, ".gnupg");
		try (TrustDbIo trustDbIo = new TrustDbIo(new File(gnuPgHome, "trustdb.gpg"));) {
			long recordNum = -1;
			TrustRecord trustRecord;
			List<byte[]> trustFingerprints = new ArrayList<>();
			while ((trustRecord = trustDbIo.getTrustRecord(++recordNum)) != null) {
				System.out.println(trustRecord);
				if (trustRecord.getType() == TrustRecordType.TRUST)
					trustFingerprints.add(((TrustRecord.Trust) trustRecord).getFingerprint());
			}

			for (byte[] trustFingerprint : trustFingerprints) {
				Trust trust = trustDbIo.getTrustByFingerprint(trustFingerprint);
				assertThat(trust).isNotNull();
			}
		}
	}

	@Test
	public void updateMyProductiveDbHashTable() throws Exception {
		String userHome = System.getProperty("user.home");
		File gnuPgHome = new File(userHome, ".gnupg");
		try (TrustDbIo trustDbIo = new TrustDbIo(new File(gnuPgHome, "trustdb.gpg"));) {
			long recordNum = -1;
			TrustRecord trustRecord;
			List<TrustRecord.Trust> trusts = new ArrayList<>();
			while ((trustRecord = trustDbIo.getTrustRecord(++recordNum)) != null) {
				if (trustRecord.getType() == TrustRecordType.TRUST)
					trusts.add((TrustRecord.Trust) trustRecord);
			}

			for (TrustRecord.Trust trust : trusts) {
				trustDbIo.putTrustRecord(trust);
			}
		}
	}

	@Test
	public void updateMyProductiveTrustDb() throws Exception {
		String userHome = System.getProperty("user.home");
		File gnuPgHome = new File(userHome, ".gnupg");

		PgpKeyRegistry pgpKeyRegistry = new PgpKeyRegistry(new File(gnuPgHome, "pubring.gpg"), new File(gnuPgHome, "secring.gpg"));
		try (TrustDb trustDb = new TrustDb(new File(gnuPgHome, "trustdb.gpg"), pgpKeyRegistry);) {
			trustDb.updateTrustDb();
		}
	}

}
