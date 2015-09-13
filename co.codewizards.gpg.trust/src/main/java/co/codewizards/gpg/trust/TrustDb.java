package co.codewizards.gpg.trust;

import static co.codewizards.gpg.trust.AssertUtil.*;

import java.io.File;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TrustDb implements AutoCloseable, TrustRecordConst {
	private static final Logger logger = LoggerFactory.getLogger(TrustDb.class);

	private final TrustDbIo trustDbIo;

	public TrustDb(File file) {
		assertNotNull("file", file);
		trustDbIo = new TrustDbIo(file);
	}

	@Override
	public void close() throws Exception {
		trustDbIo.close();
	}

	protected void resetTrustRecords() {
		TrustRecord record;
		long recordNum = 0;
		int count = 0, nreset = 0;

		while ((record = trustDbIo.getTrustRecord(++recordNum)) != null) {
			if (record.getType() == TrustRecordType.TRUST) {
				final TrustRecord.Trust trust = (TrustRecord.Trust) record;
				++count;
				if(trust.getMinOwnerTrust() != 0) {
					trust.setMinOwnerTrust((short) 0);
					trustDbIo.putTrustRecord(record);
				}
			}
			else if (record.getType() == TrustRecordType.VALID) {
				final TrustRecord.Valid valid = (TrustRecord.Valid) record;
				if (((valid.getValidity() & TRUST_MASK) != 0)
						|| valid.getMarginalCount() != 0
						|| valid.getFullCount() != 0) {

					valid.setValidity((short) (valid.getValidity() & (~TRUST_MASK)));
					valid.setMarginalCount((short) 0);
					valid.setFullCount((short) 0);
					nreset++;
					trustDbIo.putTrustRecord(record);
				}
			}
		}

		logger.debug("resetTrustRecords: {} keys processed ({} validity counts cleared)", count, nreset);
	}

	protected void initTrustDb() {
		// TODO implement this!
	}

	protected void checkTrustDbStale() {
		// TODO implement this!
	}

	protected TrustRecord.Trust getTrustByPublicKey(PGPPublicKey pk)
	{
		initTrustDb();
		TrustRecord.Trust trust = trustDbIo.getTrustByPublicKey(pk);
		return trust;
	}

	// TODO omit 'pk', because only mainPk is used.
	protected int getValidityCore(PGPPublicKey pk, String userId, PGPPublicKey mainPk) {
//		TrustRecord trec, vrec;
//		long recordNum;
//		int validity;

		initTrustDb();

		// We do not (yet) support anything else than TM_PGP.
//		/* If we have no trustdb (which also means it has not been created)
//	     and the trust-model is always, we don't know the validity -
//	     return immediately.  If we won't do that the tdbio code would try
//	     to open the trustdb and run into a fatal error.  */
//		if (trustdb_args.no_trustdb && opt.trust_model == TM_ALWAYS)
//			return TRUST_UNKNOWN;

		checkTrustDbStale();

		// We do not (yet) support anything else then TM_PGP.
//		if(opt.trust_model==TM_DIRECT)
//		{
//			/* Note that this happens BEFORE any user ID stuff is checked.
//		 The direct trust model applies to keys as a whole. */
//			validity = tdb_get_ownertrust (main_pk);
//			goto leave;
//		}

		TrustRecord.Trust trust = getTrustByPublicKey(mainPk);
		if (trust == null)
			return TRUST_UNKNOWN;

		// Loop over all user IDs
		long recordNum = trust.getValidList();
		int validity = 0;
		while (recordNum != 0) {
			TrustRecord.Valid valid = trustDbIo.getTrustRecord(recordNum, TrustRecord.Valid.class);
			assertNotNull("valid", valid);

			if (userId != null) {
//				// If a user ID is given we return the validity for that
//				// user ID ONLY.  If the namehash is not found, then there
//				// is no validity at all (i.e. the user ID wasn't signed).
//
//				if(memcmp(vrec.r.valid.namehash,uid->namehash,20)==0)
//				{
//					validity=(vrec.r.valid.validity & TRUST_MASK);
//					break;
//				}
				throw new UnsupportedOperationException("NYI");
			}
			else {
				// If no user ID is given, we take the maximum validity over all user IDs
				validity = Math.max(validity, valid.getValidity() & TRUST_MASK);
			}
			recordNum = valid.getNext();
		}

		// BC does not manage the public-keys' flags - hence we skip this. And I don't think this disabled
		// flag is so important, anyway.
		if ( (trust.getOwnerTrust() & TRUST_FLAG_DISABLED) != 0 ) {
			validity |= TRUST_FLAG_DISABLED;
//			pk->flags.disabled = 1;
		}
//		else
//			pk->flags.disabled = 0;
//
//		pk->flags.disabled_valid = 1;

		// TODO do we need pending_check_trustdb?
//			leave:
//				if (pending_check_trustdb)
//					validity |= TRUST_FLAG_PENDING_CHECK;

		return validity;
	}

}
