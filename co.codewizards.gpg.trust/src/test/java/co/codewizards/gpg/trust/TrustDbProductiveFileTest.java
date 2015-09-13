package co.codewizards.gpg.trust;

import static org.assertj.core.api.Assertions.*;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import co.codewizards.gpg.trust.TrustRecord.Trust;

public class TrustDbProductiveFileTest {

	@Test
	public void readMyProductiveTrustDb() throws Exception {
		String userHome = System.getProperty("user.home");
		TrustDbIo trustDbIo = new TrustDbIo(new File(userHome, ".gnupg/trustdb.gpg"));

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
