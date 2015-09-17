package co.codewizards.gpg.trust;

import static co.codewizards.gpg.trust.Util.*;

import java.io.File;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import co.codewizards.gpg.trust.key.PgpKey;
import co.codewizards.gpg.trust.key.PgpKeyFingerprint;
import co.codewizards.gpg.trust.key.PgpKeyId;
import co.codewizards.gpg.trust.key.PgpKeyRegistry;
import co.codewizards.gpg.trust.key.PgpUserId;
import co.codewizards.gpg.trust.key.PgpUserIdNameHash;

public class TrustDb implements AutoCloseable, TrustConst {
	private static final Logger logger = LoggerFactory.getLogger(TrustDb.class);

	private final TrustDbIo trustDbIo;
	private final PgpKeyRegistry pgpKeyRegistry;

	private long startTime;
	private long nextExpire;
	private Map<PgpKeyFingerprint, PgpKeyTrust> fingerprint2PgpKeyTrust;
	private Set<PgpKeyFingerprint> klist;
	private Set<PgpKeyFingerprint> fullTrust;
	private DateFormat dateFormatIso8601;
	private DateFormat dateFormatIso8601WithTime;

	public TrustDb(final File file, final PgpKeyRegistry pgpKeyRegistry) {
		assertNotNull("file", file);
		this.pgpKeyRegistry = assertNotNull("pgpKeyRegistry", pgpKeyRegistry);
		this.trustDbIo = new TrustDbIo(file);
	}

	@Override
	public void close() throws Exception {
		trustDbIo.close();
	}

	public DateFormat getDateFormatIso8601() {
		if (dateFormatIso8601 == null)
			dateFormatIso8601 = new SimpleDateFormat("yyyy-MM-dd");

		return dateFormatIso8601;
	}

	public DateFormat getDateFormatIso8601WithTime() {
		if (dateFormatIso8601WithTime == null)
			dateFormatIso8601WithTime = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");

		return dateFormatIso8601WithTime;
	}

	protected PgpKeyTrust getPgpKeyTrust(final PgpKey pgpKey) {
		PgpKeyTrust pgpKeyTrust = fingerprint2PgpKeyTrust.get(pgpKey.getPgpKeyFingerprint());
		if (pgpKeyTrust == null) {
			pgpKeyTrust = new PgpKeyTrust(pgpKey);
			fingerprint2PgpKeyTrust.put(pgpKeyTrust.getPgpKeyFingerprint(), pgpKeyTrust);
		}
		return pgpKeyTrust;
	}

	// reset_trust_records(void)
	protected void resetTrustRecords() {
		TrustRecord record;
		long recordNum = 0;
		int count = 0, nreset = 0;

		while ((record = trustDbIo.getTrustRecord(++recordNum)) != null) {
			if (record.getType() == TrustRecordType.TRUST) {
				final TrustRecord.Trust trust = (TrustRecord.Trust) record;
				++count;
				if (trust.getMinOwnerTrust() != 0) {
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

	/**
	 * Gets the assigned ownertrust value for the given public key.
	 * The key should be the primary key.
	 */
	public int getOwnerTrust(PGPPublicKey pk)
	{
//		if (trustdb_args.no_trustdb && opt.trust_model == TM_ALWAYS)
//			return TRUST_UNKNOWN; // TODO should we really support this?!

		TrustRecord.Trust trust = getTrustByPublicKey(pk);
		if (trust == null)
			return TRUST_UNKNOWN;

		return trust.getOwnerTrust();
	}

	public void setOwnerTrust(PGPPublicKey pk, int ownerTrust) {
		assertNotNull("pk", pk);
		assertNonNegativeShort("ownerTrust", ownerTrust);
		// TODO we should probably test the ownerTrust a bit more thoroughly to prevent illegal data!

		TrustRecord.Trust trust = getTrustByPublicKey(pk);
		if (trust == null) {
			// No record yet - create a new one.
			trust = new TrustRecord.Trust();
			trust.setFingerprint(pk.getFingerprint());
		}
		trust.setOwnerTrust((short) ownerTrust);
		trustDbIo.putTrustRecord(trust);

		markTrustDbStale();
		trustDbIo.flush();
	}

	protected TrustRecord.Trust getTrustByPublicKey(PGPPublicKey pk)
	{
		TrustRecord.Trust trust = trustDbIo.getTrustByPublicKey(pk);
		return trust;
	}

	public synchronized int getValidity(final PGPPublicKey publicKey) {
		return getValidity(publicKey, (PgpUserIdNameHash) null);
	}

	public synchronized int getValidity(final PGPPublicKey publicKey, final String userId) {
		return getValidity(publicKey, userId == null ? null : PgpUserIdNameHash.createFromUserId(userId));
	}

	public synchronized int getValidity(PGPPublicKey publicKey, PGPUserAttributeSubpacketVector userAttribute) {
		return getValidity(publicKey, userAttribute == null ? null : PgpUserIdNameHash.createFromUserAttribute(userAttribute));
	}

	protected synchronized int getValidity(final PGPPublicKey publicKey, final PgpUserIdNameHash pgpUserIdNameHash) {
		assertNotNull("publicKey", publicKey);

		TrustRecord.Trust trust = getTrustByPublicKey(publicKey);
		if (trust == null)
			return TRUST_UNKNOWN;

		// Loop over all user IDs
		long recordNum = trust.getValidList();
		int validity = 0;
		while (recordNum != 0) {
			TrustRecord.Valid valid = trustDbIo.getTrustRecord(recordNum, TrustRecord.Valid.class);
			assertNotNull("valid", valid);

			if (pgpUserIdNameHash != null) {
				// If a user ID is given we return the validity for that
				// user ID ONLY.  If the namehash is not found, then there
				// is no validity at all (i.e. the user ID wasn't signed).
				if (pgpUserIdNameHash.equals(valid.getNameHash())) {
					validity = valid.getValidity();
					break;
				}
			}
			else {
				// If no user ID is given, we take the maximum validity over all user IDs
				validity = Math.max(validity, valid.getValidity() & TRUST_MASK);
			}
			recordNum = valid.getNext();
		}

		if ( (trust.getOwnerTrust() & TRUST_FLAG_DISABLED) != 0 )
			validity |= TRUST_FLAG_DISABLED;

		if (publicKey.isRevoked())
			validity |= TRUST_FLAG_REVOKED;

		if (isTrustDbStale())
			validity |= TRUST_FLAG_PENDING_CHECK;

		return validity;
	}


//	// TO DO omit 'pk', because only mainPk is used.
//	protected int getValidityCore(PGPPublicKey pk, String userId, PGPPublicKey mainPk) {
//		//		TrustRecord trec, vrec;
//		//		long recordNum;
//		//		int validity;
//
//		initTrustDb();
//
//		// We do not (yet) support anything else than TM_PGP.
//		//		/* If we have no trustdb (which also means it has not been created)
//		//	     and the trust-model is always, we don't know the validity -
//		//	     return immediately.  If we won't do that the tdbio code would try
//		//	     to open the trustdb and run into a fatal error.  */
//		//		if (trustdb_args.no_trustdb && opt.trust_model == TM_ALWAYS)
//		//			return TRUST_UNKNOWN;
//
//		checkTrustDbStale();
//
//		// We do not (yet) support anything else then TM_PGP.
//		//		if(opt.trust_model==TM_DIRECT)
//		//		{
//		//			/* Note that this happens BEFORE any user ID stuff is checked.
//		//		 The direct trust model applies to keys as a whole. */
//		//			validity = tdb_get_ownertrust (main_pk);
//		//			goto leave;
//		//		}
//
//		TrustRecord.Trust trust = getTrustByPublicKey(mainPk);
//		if (trust == null)
//			return TRUST_UNKNOWN;
//
//		// Loop over all user IDs
//		long recordNum = trust.getValidList();
//		int validity = 0;
//		while (recordNum != 0) {
//			TrustRecord.Valid valid = trustDbIo.getTrustRecord(recordNum, TrustRecord.Valid.class);
//			assertNotNull("valid", valid);
//
//			if (userId != null) {
//				//				// If a user ID is given we return the validity for that
//				//				// user ID ONLY.  If the namehash is not found, then there
//				//				// is no validity at all (i.e. the user ID wasn't signed).
//				//
//				//				if(memcmp(vrec.r.valid.namehash,uid->namehash,20)==0)
//				//				{
//				//					validity=(vrec.r.valid.validity & TRUST_MASK);
//				//					break;
//				//				}
//				throw new UnsupportedOperationException("NYI");
//			}
//			else {
//				// If no user ID is given, we take the maximum validity over all user IDs
//				validity = Math.max(validity, valid.getValidity() & TRUST_MASK);
//			}
//			recordNum = valid.getNext();
//		}
//
//		// BC does not manage the public-keys' flags - hence we skip this. And I don't think this disabled
//		// flag is so important, anyway.
//		if ( (trust.getOwnerTrust() & TRUST_FLAG_DISABLED) != 0 ) {
//			validity |= TRUST_FLAG_DISABLED;
//			//			pk->flags.disabled = 1;
//		}
//		//		else
//		//			pk->flags.disabled = 0;
//		//
//		//		pk->flags.disabled_valid = 1;
//
//		// TODO do we need pending_check_trustdb?
//		//			leave:
//		//				if (pending_check_trustdb)
//		//					validity |= TRUST_FLAG_PENDING_CHECK;
//
//		return validity;
//	}

	// static void update_validity (PKT_public_key *pk, PKT_user_id *uid, int depth, int validity)
	protected void updateValidity(PgpUserId pgpUserId, int depth, int validity, int fullCount, int marginalCount) {
		assertNotNull("pgpUserId", pgpUserId);
		assertNonNegativeShort("depth", depth);
		assertNonNegativeShort("validity", validity);
		assertNonNegativeShort("fullCount", fullCount);
		assertNonNegativeShort("marginalCount", marginalCount);

		TrustRecord.Trust trust = getTrustByPublicKey(pgpUserId.getPgpKey().getPublicKey());
		if (trust == null) {
			// No record yet - create a new one.
			trust = new TrustRecord.Trust();
			trust.setFingerprint(pgpUserId.getPgpKey().getPgpKeyFingerprint().getBytes());
			trustDbIo.putTrustRecord(trust);
		}

		TrustRecord.Valid valid = null;

		// locate an existing Valid record
		final byte[] pgpUserIdNameHashBytes = pgpUserId.getNameHash().getBytes();
		long recordNum = trust.getValidList();
		while (recordNum != 0) {
			valid = trustDbIo.getTrustRecord(recordNum, TrustRecord.Valid.class);
			if (Arrays.equals(valid.getNameHash(), pgpUserIdNameHashBytes))
				break;

			recordNum = valid.getNext();
		}

		if (recordNum == 0) { // insert a new validity record
			valid = new TrustRecord.Valid();
			valid.setNameHash(pgpUserIdNameHashBytes);
			valid.setNext(trust.getValidList());
			trustDbIo.putTrustRecord(valid); // assigns the recordNum of the new record
			trust.setValidList(valid.getRecordNum());
		}

		valid.setValidity((short) validity);
		valid.setFullCount((short) fullCount);
		valid.setMarginalCount((short) marginalCount);
		trust.setDepth((short) depth);
		trustDbIo.putTrustRecord(trust);
		trustDbIo.putTrustRecord(valid);
	}

	private static void assertNonNegativeShort(final String name, final int value) {
		assertNotNull("name", name);

		if (value < 0)
			throw new IllegalArgumentException(name + " < 0");

		if (value > Short.MAX_VALUE)
			throw new IllegalArgumentException(name + " > Short.MAX_VALUE");
	}

	/**
	 * Marks all those keys that we have a secret key for as ultimately trusted. If we have a secret/private key,
	 * we assume it to be *our* key and we always trust ourselves.
	 */
	public void updateUltimatelyTrustedKeysFromAvailableSecretKeys(boolean onlyIfMissing) {
		for (final PgpKey masterKey : pgpKeyRegistry.getMasterKeys()) {
			if (masterKey.getSecretKey() == null)
				continue;

			TrustRecord.Trust trust = trustDbIo.getTrustByPublicKey(masterKey.getPublicKey());
			if (trust == null
					|| trust.getOwnerTrust() == TRUST_UNKNOWN
					|| !onlyIfMissing) {

				if (trust == null) {
					trust = new TrustRecord.Trust();
					trust.setFingerprint(masterKey.getPgpKeyFingerprint().getBytes());
				}

				trust.setDepth((short) 0);
				trust.setOwnerTrust((short) TRUST_ULTIMATE);
				trustDbIo.putTrustRecord(trust);
			}
		}
	}

	protected Set<PgpKeyFingerprint> getUltimatelyTrustedKeyFingerprints() {
		Set<PgpKeyFingerprint> result = new HashSet<PgpKeyFingerprint>();
		TrustRecord record;
		long recordNum = 0;
		while ((record = trustDbIo.getTrustRecord(++recordNum)) != null) {
			if (record.getType() == TrustRecordType.TRUST) {
				TrustRecord.Trust trust = (TrustRecord.Trust) record;
				if ((trust.getOwnerTrust() & TRUST_MASK) == TRUST_ULTIMATE)
					result.add(new PgpKeyFingerprint(trust.getFingerprint()));
			}
		}
		return result;
	}

//	/**
//	 * Scan all keys and return a key_array of all suitable keys from
//	 * klist.  The caller has to pass keydb handle so that we don't use
//	 * to create our own.  Returns either a key_array or NULL in case of
//	 * an error.  No results found are indicated by an empty array.
//	 * Caller hast to release the returned array.
//	 */
//	//static struct key_array * validate_key_list (KEYDB_HANDLE hd, KeyHashTable full_trust, struct key_item *klist, u32 curtime, u32 *next_expire)
//	public Set<PgpKeyFingerprint> validateKeyList() {
////		KBNODE keyblock = NULL;
////		struct key_array *keys = NULL;
////		size_t nkeys, maxkeys;
////		int rc;
////		KEYDB_SEARCH_DESC desc;
////
////		maxkeys = 1000;
////		keys = xmalloc ((maxkeys+1) * sizeof *keys);
////		nkeys = 0;
////
////		rc = keydb_search_reset (hd);
////		if (rc)
////		{
////			log_error ("keydb_search_reset failed: %s\n", gpg_strerror (rc));
////			xfree (keys);
////			return NULL;
////		}
////
////		memset (&desc, 0, sizeof desc);
////		desc.mode = KEYDB_SEARCH_MODE_FIRST;
////		desc.skipfnc = search_skipfnc;
////		desc.skipfncvalue = full_trust;
////		rc = keydb_search (hd, &desc, 1, NULL);
////		if (gpg_err_code (rc) == GPG_ERR_NOT_FOUND)
////		{
////			keys[nkeys].keyblock = NULL;
////			return keys;
////		}
////		if (rc)
////		{
////			log_error ("keydb_search_first failed: %s\n", gpg_strerror (rc));
////			xfree (keys);
////			return NULL;
////		}
////
////		desc.mode = KEYDB_SEARCH_MODE_NEXT; // change mode
////		do
////		{
////			PKT_public_key *pk;
////
////			if (gpg_err_code (rc) == GPG_ERR_LEGACY_KEY)
////				continue;
////
////			rc = keydb_get_keyblock (hd, &keyblock);
////			if (rc)
////			{
////				log_error ("keydb_get_keyblock failed: %s\n", gpg_strerror (rc));
////				xfree (keys);
////				return NULL;
////			}
////
////			if ( keyblock->pkt->pkttype != PKT_PUBLIC_KEY)
////			{
////				log_debug ("ooops: invalid pkttype %d encountered\n",
////						keyblock->pkt->pkttype);
////				dump_kbnode (keyblock);
////				release_kbnode(keyblock);
////				continue;
////			}
////
////			/* prepare the keyblock for further processing */
////			merge_keys_and_selfsig (keyblock);
////			clear_kbnode_flags (keyblock);
////			pk = keyblock->pkt->pkt.public_key;
////			if (pk->has_expired || pk->flags.revoked)
////			{
////				/* it does not make sense to look further at those keys */
////				mark_keyblock_seen (full_trust, keyblock);
////			}
////			else if (validate_one_keyblock (keyblock, klist, curtime, next_expire))
////			{
////				KBNODE node;
////
////				if (pk->expiredate && pk->expiredate >= curtime
////						&& pk->expiredate < *next_expire)
////					*next_expire = pk->expiredate;
////
////					if (nkeys == maxkeys) {
////						maxkeys += 1000;
////						keys = xrealloc (keys, (maxkeys+1) * sizeof *keys);
////					}
////					keys[nkeys++].keyblock = keyblock;
////
////					/* Optimization - if all uids are fully trusted, then we
////		     never need to consider this key as a candidate again. */
////
////					for (node=keyblock; node; node = node->next)
////						if (node->pkt->pkttype == PKT_USER_ID && !(node->flag & 4))
////							break;
////
////					if(node==NULL)
////						mark_keyblock_seen (full_trust, keyblock);
////
////					keyblock = NULL;
////			}
////
////			release_kbnode (keyblock);
////			keyblock = NULL;
////		}
////		while (!(rc = keydb_search (hd, &desc, 1, NULL))
////				|| gpg_err_code (rc) == GPG_ERR_LEGACY_KEY);
////
////		if (rc && gpg_err_code (rc) != GPG_ERR_NOT_FOUND)
////		{
////			log_error ("keydb_search_next failed: %s\n", gpg_strerror (rc));
////			xfree (keys);
////			return NULL;
////		}
////
////		keys[nkeys].keyblock = NULL;
////		return keys;
//
//		final Set<PgpKeyFingerprint> signedPgpKeyFingerprints = new HashSet<>();
//		for (PgpKeyFingerprint signingPgpKeyFingerprint : klist)
//			signedPgpKeyFingerprints.addAll(pgpKeyRegistry.getPgpKeyFingerprintsSignedBy(signingPgpKeyFingerprint));
//
//		signedPgpKeyFingerprints.removeAll(fullTrust);
//		for (final PgpKeyFingerprint pgpKeyFingerprint : signedPgpKeyFingerprints) {
//			final PgpKey pgpKey = pgpKeyRegistry.getPgpKey(pgpKeyFingerprint);
//			if (pgpKey == null) {
//				logger.warn("key disappeared: fingerprint='{}'", pgpKeyFingerprint);
//				continue;
//			}
//
//			if (isExpired(pgpKey.getPublicKey()) || pgpKey.getPublicKey().isRevoked()) {
//				// it does not make sense to look further at those keys
//				fullTrust.add(pgpKeyFingerprint);
//			}
//			else if (validateKey(pgpKey)) {
//
//			}
//		}
//
//	}
//
//	/*
//	 * Return true if the key is signed by one of the keys in the given
//	 * key ID list.  User IDs with a valid signature are marked by node
//	 * flags as follows:
//	 *  flag bit 0: There is at least one signature
//	 *           1: There is marginal confidence that this is a legitimate uid
//	 *           2: There is full confidence that this is a legitimate uid.
//	 *           8: Used for internal purposes.
//	 *           9: Ditto (in mark_usable_uid_certs())
//	 *          10: Ditto (ditto)
//	 * This function assumes that all kbnode flags are cleared on entry.
//	 */
//	// static int validate_one_keyblock (KBNODE kb, struct key_item *klist, u32 curtime, u32 *next_expire)
//	private boolean validateKey(PgpKey pgpKey) {
//		struct key_item *kr;
//		KBNODE node, uidnode=NULL;
//		PKT_user_id *uid=NULL;
//		PKT_public_key *pk = kb->pkt->pkt.public_key;
//		u32 main_kid[2];
//		int issigned=0, any_signed = 0;
//
//		keyid_from_pk(pk, main_kid);
//		for (node=kb; node; node = node->next)
//		{
//			/* A bit of discussion here: is it better for the web of trust
//		 to be built among only self-signed uids?  On the one hand, a
//		 self-signed uid is a statement that the key owner definitely
//		 intended that uid to be there, but on the other hand, a
//		 signed (but not self-signed) uid does carry trust, of a sort,
//		 even if it is a statement being made by people other than the
//		 key owner "through" the uids on the key owner's key.  I'm
//		 going with the latter.  However, if the user ID was
//		 explicitly revoked, or passively allowed to expire, that
//		 should stop validity through the user ID until it is
//		 resigned.  -dshaw */
//
//			if (node->pkt->pkttype == PKT_USER_ID
//					&& !node->pkt->pkt.user_id->is_revoked
//					&& !node->pkt->pkt.user_id->is_expired)
//			{
//				if (uidnode && issigned)
//				{
//					if (uid->help_full_count >= opt.completes_needed
//							|| uid->help_marginal_count >= opt.marginals_needed )
//						uidnode->flag |= 4;
//						else if (uid->help_full_count || uid->help_marginal_count)
//							uidnode->flag |= 2;
//							uidnode->flag |= 1;
//							any_signed = 1;
//				}
//				uidnode = node;
//				uid=uidnode->pkt->pkt.user_id;
//
//				/* If the selfsig is going to expire... */
//				if(uid->expiredate && uid->expiredate<*next_expire)
//					*next_expire = uid->expiredate;
//
//					issigned = 0;
//					get_validity_counts(pk,uid);
//					mark_usable_uid_certs (kb, uidnode, main_kid, klist,
//							curtime, next_expire);
//			}
//			else if (node->pkt->pkttype == PKT_SIGNATURE
//					&& (node->flag & (1<<8)) && uid)
//			{
//				/* Note that we are only seeing unrevoked sigs here */
//				PKT_signature *sig = node->pkt->pkt.signature;
//
//				kr = is_in_klist (klist, sig);
//				/* If the trust_regexp does not match, it's as if the sig
//	             did not exist.  This is safe for non-trust sigs as well
//	             since we don't accept a regexp on the sig unless it's a
//	             trust sig. */
//				if (kr && (!kr->trust_regexp
//						|| opt.trust_model != TM_PGP
//						|| (uidnode
//								&& check_regexp(kr->trust_regexp,
//										uidnode->pkt->pkt.user_id->name))))
//				{
//					/* Are we part of a trust sig chain?  We always favor
//	                 the latest trust sig, rather than the greater or
//	                 lesser trust sig or value.  I could make a decent
//	                 argument for any of these cases, but this seems to be
//	                 what PGP does, and I'd like to be compatible. -dms */
//					if (opt.trust_model == TM_PGP
//							&& sig->trust_depth
//							&& pk->trust_timestamp <= sig->timestamp)
//					{
//						unsigned char depth;
//
//						/* If the depth on the signature is less than the
//			     chain currently has, then use the signature depth
//			     so we don't increase the depth beyond what the
//			     signer wanted.  If the depth on the signature is
//			     more than the chain currently has, then use the
//			     chain depth so we use as much of the signature
//			     depth as the chain will permit.  An ultimately
//			     trusted signature can restart the depth to
//			     whatever level it likes. */
//
//						if (sig->trust_depth < kr->trust_depth
//								|| kr->ownertrust == TRUST_ULTIMATE)
//							depth = sig->trust_depth;
//							else
//								depth = kr->trust_depth;
//
//								if (depth)
//								{
//									if(DBG_TRUST)
//										log_debug ("trust sig on %s, sig depth is %d,"
//												" kr depth is %d\n",
//												uidnode->pkt->pkt.user_id->name,
//												sig->trust_depth,
//												kr->trust_depth);
//
//									/* If we got here, we know that:
//
//				 this is a trust sig.
//
//				 it's a newer trust sig than any previous trust
//				 sig on this key (not uid).
//
//				 it is legal in that it was either generated by an
//				 ultimate key, or a key that was part of a trust
//				 chain, and the depth does not violate the
//				 original trust sig.
//
//				 if there is a regexp attached, it matched
//				 successfully.
//									 */
//
//									if (DBG_TRUST)
//										log_debug ("replacing trust value %d with %d and "
//												"depth %d with %d\n",
//												pk->trust_value,sig->trust_value,
//												pk->trust_depth,depth);
//
//									pk->trust_value = sig->trust_value;
//									pk->trust_depth = depth-1;
//
//									/* If the trust sig contains a regexp, record it
//				 on the pk for the next round. */
//									if (sig->trust_regexp)
//										pk->trust_regexp = sig->trust_regexp;
//								}
//					}
//
//					if (kr->ownertrust == TRUST_ULTIMATE)
//						uid->help_full_count = opt.completes_needed;
//						else if (kr->ownertrust == TRUST_FULLY)
//							uid->help_full_count++;
//							else if (kr->ownertrust == TRUST_MARGINAL)
//								uid->help_marginal_count++;
//								issigned = 1;
//				}
//			}
//		}
//
//		if (uidnode && issigned)
//		{
//			if (uid->help_full_count >= opt.completes_needed
//					|| uid->help_marginal_count >= opt.marginals_needed )
//				uidnode->flag |= 4;
//				else if (uid->help_full_count || uid->help_marginal_count)
//					uidnode->flag |= 2;
//					uidnode->flag |= 1;
//					any_signed = 1;
//		}
//
//		return any_signed;
//	}


	public boolean isExpired(PGPPublicKey publicKey) {
		assertNotNull("publicKey", publicKey);

		final Date creationTime = publicKey.getCreationTime();

		final long validSeconds = publicKey.getValidSeconds();
		if (validSeconds != 0) {
			long validUntilTimestamp = creationTime.getTime() + (validSeconds * 1000);
			return validUntilTimestamp < System.currentTimeMillis();
		}
		return false;

		// TODO there seem to be keys (very old keys) that seem to encode the validity differently.
		// For example, the real key 86A331B667F0D02F is expired according to my gpg, but it
		// is not expired according to this code :-( I experimented with checking the userIds, but to no avail.
		// It's a very small number of keys only, hence I ignore it now ;-)
	}

	public boolean isDisabled(PGPPublicKey publicKey) {
		assertNotNull("publicKey", publicKey);
		TrustRecord.Trust trust = trustDbIo.getTrustByFingerprint(publicKey.getFingerprint());
		if (trust == null)
			return false;

		return (trust.getOwnerTrust() & TRUST_FLAG_DISABLED) != 0;
	}

	public void setDisabled(PGPPublicKey publicKey) {
		assertNotNull("publicKey", publicKey);
		TrustRecord.Trust trust = trustDbIo.getTrustByFingerprint(publicKey.getFingerprint());
		if (trust == null) {
			trust = new TrustRecord.Trust();
			trust.setFingerprint(publicKey.getFingerprint());
		}
		trustDbIo.putTrustRecord(trust);
		trustDbIo.flush();
	}

//	/**
//	 * Run the key validation procedure.
//	 *
//	 * This works this way:
//	 * Step 1: Find all ultimately trusted keys (UTK).
//	 *         mark them all as seen and put them into klist.
//	 * Step 2: loop max_cert_times
//	 * Step 3:   if OWNERTRUST of any key in klist is undefined
//	 *             ask user to assign ownertrust -- THIS IMPLEMENTATION IS NEVER INTERACTIVE!
//	 * Step 4:   Loop over all keys in the keyDB which are not marked seen
//	 * Step 5:     if key is revoked or expired
//	 *                mark key as seen
//	 *                continue loop at Step 4
//	 * Step 6:     For each user ID of that key signed by a key in klist
//	 *                Calculate validity by counting trusted signatures.
//	 *                Set validity of user ID
//	 * Step 7:     If any signed user ID was found
//	 *                mark key as seen
//	 *             End Loop
//	 * Step 8:   Build a new klist from all fully trusted keys from step 6
//	 *           End Loop
//	 *         Ready
//	 *
//	 */
//	// static int validate_keys (int interactive) -- this implementation, however, is never interactive!!!
//	protected synchronized void updateTrustDb() {
//		final Config config = Config.getInstance();
//		int rc = 0;
//		int quit=0;
////		struct key_item *klist = NULL;
////		struct key_item *k;
////		struct key_array *keys = NULL;
////		struct key_array *kar;
////		KEYDB_HANDLE kdb = NULL;
////		KBNODE node;
//		int ot_unknown, ot_undefined, ot_never, ot_marginal, ot_full, ot_ultimate;
//
//		fingerprint2PgpKeyTrust = new HashMap<>();
//		stored = new HashSet<>();
//		used = new HashSet<>();
//		fullTrust = new HashSet<>();
//		try {
//			long start_time, next_expire;
//
//	//		/* Make sure we have all sigs cached.  TODO: This is going to
//	//	     require some architectual re-thinking, as it is agonizingly slow.
//	//	     Perhaps combine this with reset_trust_records(), or only check
//	//	     the caches on keys that are actually involved in the web of
//	//	     trust. */
//	//		keydb_rebuild_caches(0);
//
//			start_time = System.currentTimeMillis() / 1000;
//			next_expire = 0xffffffff; /* set next expire to the year 2106 */
//
//			resetTrustRecords();
//
//			final Set<PgpKeyFingerprint> ultimatelyTrustedKeyFingerprints = getUltimatelyTrustedKeyFingerprints();
//			if (ultimatelyTrustedKeyFingerprints.isEmpty()) {
//				logger.warn("updateTrustDb: There are no ultimately trusted keys!");
//				return;
//			}
//
//			// mark all UTKs as used and fully_trusted and set validity to ultimate
//			for (final PgpKeyFingerprint utkFpr : ultimatelyTrustedKeyFingerprints) {
//				final PgpKey utk = pgpKeyRegistry.getPgpKey(utkFpr);
//				if (utk == null) {
//					logger.warn("public key of ultimately trusted key '{}' not found!", utkFpr.toHumanString());
//					continue;
//				}
//
//				used.add(utkFpr);
//				stored.add(utkFpr);
//				fullTrust.add(utkFpr);
//
//				for (PgpUserId pgpUserId : utk.getPgpUserIds())
//					updateValidity(pgpUserId, 0, TRUST_ULTIMATE);
//
//				if (utk.getPublicKey().getValidSeconds() != 0) {
//					long expiredate = (utk.getPublicKey().getCreationTime().getTime() / 1000)
//							+ utk.getPublicKey().getValidSeconds();
//
//					if (expiredate >= start_time && expiredate < next_expire)
//						next_expire = expiredate;
//				}
//			}
//
//			klist = ultimatelyTrustedKeyFingerprints;
//
//
//			logger.info("{} marginal(s) needed, {} complete(s) needed, {} trust model",
//					config.getMarginalsNeeded(), config.getCompletesNeeded(), config.getTrustModelAsString());
//
//			for (int depth=0; depth < Config.getInstance().getMaxCertDepth(); ++depth) {
//				int valids=0, key_count;
//				// See whether we should assign ownertrust values to the keys in klist.
//				ot_unknown = ot_undefined = ot_never = 0;
//				ot_marginal = ot_full = ot_ultimate = 0;
//				for (final PgpKeyFingerprint fingerprint : klist) {
//					PgpKey pgpKey = pgpKeyRegistry.getPgpKeyOrFail(fingerprint);
//					PgpKeyTrust pgpKeyTrust = getPgpKeyTrust(pgpKey);
//					TrustRecord.Trust trust = trustDbIo.getTrustByFingerprint(fingerprint.getBytes());
//					int min = 0;
//
//					/* 120 and 60 are as per RFC2440 */
//					if (pgpKeyTrust.getTrustValue() >= 120)
//						min = TRUST_FULLY;
//					else if  (pgpKeyTrust.getTrustValue() >= 60)
//						min = TRUST_MARGINAL;
//
//					if (trust == null || min != trust.getMinOwnerTrust()) {
//						if (trust == null) {
//							trust = new TrustRecord.Trust();
//							trust.setFingerprint(fingerprint.getBytes());
//						}
//						trust.setMinOwnerTrust((short) min);
//						trustDbIo.putTrustRecord(trust);
//					}
//
//					// This can happen during transition from an old trustdb before trust sigs. It can also
//					// happen if a user uses two different versions of GnuPG or changes the --trust-model setting.
//					if (trust.getOwnerTrust() < min) {
//						logger.debug("key '{}': overriding ownertrust '{}' with '{}'",
//								pgpKey.getPgpKeyId().toHumanString(),
//								trust.getOwnerTrust(),
//								min);
//
//						trust.setOwnerTrust((short) min);
//						trustDbIo.putTrustRecord(trust);
//					}
//
//					if (trust.getOwnerTrust() == TRUST_UNKNOWN)
//						++ot_unknown;
//					else if (trust.getOwnerTrust() == TRUST_UNDEFINED)
//						++ot_undefined;
//					else if (trust.getOwnerTrust() == TRUST_NEVER)
//						++ot_never;
//					else if (trust.getOwnerTrust() == TRUST_MARGINAL)
//						++ot_marginal;
//					else if (trust.getOwnerTrust() == TRUST_FULLY)
//						++ot_full;
//					else if (trust.getOwnerTrust() == TRUST_ULTIMATE)
//						++ot_ultimate;
//
//					++valids;
//				}
//
//				// Find all keys which are signed by a key in klist
//				Set<PgpKeyFingerprint> keys = validateKeyList(); //kdb, full_trust, klist, start_time, &next_expire);
//				key_count = keys.size();
//
//				// Store the calculated valididation status somewhere
//				for (kar=keys; kar->keyblock; kar++)
//					store_validation_status (depth, kar->keyblock, stored);
//
//				if (logger.isInfoEnabled()) {
//					logger.info(String.format("depth: %d  valid: %3d  signed: %3d  trust: %d-, %dq, %dn, %dm, %df, %du",
//							depth, valids, key_count, ot_unknown, ot_undefined, ot_never, ot_marginal, ot_full, ot_ultimate));
//				}
//
//				/* Build a new kdlist from all fully valid keys in KEYS */
//				if (klist != utk_list)
//					release_key_items (klist);
//				klist = NULL;
//				for (kar=keys; kar->keyblock; kar++)
//				{
//					for (node=kar->keyblock; node; node = node->next)
//					{
//						if (node->pkt->pkttype == PKT_USER_ID && (node->flag & 4))
//						{
//							u32 kid[2];
//
//							/* have we used this key already? */
//							keyid_from_pk (kar->keyblock->pkt->pkt.public_key, kid);
//							if(test_key_hash_table(used,kid)==0)
//							{
//								/* Normally we add both the primary and subkey
//					 ids to the hash via mark_keyblock_seen, but
//					 since we aren't using this hash as a skipfnc,
//					 that doesn't matter here. */
//								add_key_hash_table (used,kid);
//								k = new_key_item ();
//								k->kid[0]=kid[0];
//								k->kid[1]=kid[1];
//								k->ownertrust =
//										(tdb_get_ownertrust
//												(kar->keyblock->pkt->pkt.public_key) & TRUST_MASK);
//								k->min_ownertrust = tdb_get_min_ownertrust
//										(kar->keyblock->pkt->pkt.public_key);
//								k->trust_depth=
//										kar->keyblock->pkt->pkt.public_key->trust_depth;
//										k->trust_value=
//												kar->keyblock->pkt->pkt.public_key->trust_value;
//												if(kar->keyblock->pkt->pkt.public_key->trust_regexp)
//													k->trust_regexp=
//													xstrdup(kar->keyblock->pkt->
//													pkt.public_key->trust_regexp);
//													k->next = klist;
//													klist = k;
//													break;
//							}
//						}
//					}
//				}
//				release_key_array (keys);
//				keys = NULL;
//				if (!klist)
//					break; /* no need to dive in deeper */
//			}
//
//			leave:
//				keydb_release (kdb);
//			release_key_array (keys);
//			release_key_items (klist);
//			release_key_hash_table (full_trust);
//			release_key_hash_table (used);
//			release_key_hash_table (stored);
//			if (!rc && !quit) /* mark trustDB as checked */
//			{
//				if (next_expire == 0xffffffff || next_expire < start_time )
//					tdbio_write_nextcheck (0);
//				else
//				{
//					tdbio_write_nextcheck (next_expire);
//					log_info (_("next trustdb check due at %s\n"),
//							strtimestamp (next_expire));
//				}
//
//				if(tdbio_update_version_record()!=0)
//				{
//					log_error(_("unable to update trustdb version record: "
//							"write failed: %s\n"), gpg_strerror (rc));
//					tdbio_invalid();
//				}
//
//				do_sync ();
//				pending_check_trustdb = 0;
//			}
//
//			return rc;
//		} finally {
//			fingerprint2PgpKeyTrust = null;
//			klist = null;
//			stored = null;
//			used = null;
//			fullTrust = null;
//		}
//	}

	public synchronized boolean isTrustDbStale() {
		final Config config = Config.getInstance();
		final TrustRecord.Version version = trustDbIo.getTrustRecord(0, TrustRecord.Version.class);
		assertNotNull("version", version);

		if (config.getTrustModel() != version.getTrustModel()) {
			TrustModel configTrustModel;
			try {
				configTrustModel = TrustModel.fromNumericId(config.getTrustModel());
			} catch (IllegalArgumentException x) {
				configTrustModel = null;
			}

			TrustModel versionTrustModel;
			try {
				versionTrustModel = TrustModel.fromNumericId(version.getTrustModel());
			} catch (IllegalArgumentException x) {
				versionTrustModel = null;
			}

			logger.debug("isTrustDbStale: stale=true config.trustModel={} ({}) trustDb.trustModel={} ({})",
					config.getTrustModel(), configTrustModel, version.getTrustModel(), versionTrustModel);

			return true;
		}

		if (config.getCompletesNeeded() != version.getCompletesNeeded()) {
			logger.debug("isTrustDbStale: stale=true config.completesNeeded={} trustDb.completesNeeded={}",
					config.getCompletesNeeded(), version.getCompletesNeeded());

			return true;
		}

		if (config.getMarginalsNeeded() != version.getMarginalsNeeded()) {
			logger.debug("isTrustDbStale: stale=true config.marginalsNeeded={} trustDb.marginalsNeeded={}",
					config.getMarginalsNeeded(), version.getMarginalsNeeded());

			return true;
		}

		if (config.getMaxCertDepth() != version.getCertDepth()) {
			logger.debug("isTrustDbStale: stale=true config.maxCertDepth={} trustDb.maxCertDepth={}",
					config.getMaxCertDepth(), version.getCertDepth());

			return true;
		}

		final Date now = new Date();
		if (version.getNextCheck().before(now)) {
			logger.debug("isTrustDbStale: stale=true nextCheck={} now={}",
					getDateFormatIso8601WithTime().format(version.getNextCheck()),
					getDateFormatIso8601WithTime().format(now));

			return true;
		}

		logger.trace("isTrustDbStale: stale=false");
		return false;
	}

	protected synchronized void markTrustDbStale() {
		final TrustRecord.Version version = trustDbIo.getTrustRecord(0, TrustRecord.Version.class);
		assertNotNull("version", version);
		version.setNextCheck(new Date(0));
		trustDbIo.putTrustRecord(version);
	}

	public synchronized void updateTrustDbIfNeeded() {
		if (isTrustDbStale())
			updateTrustDb();
	}

	public synchronized void updateTrustDb() {
		final Config config = Config.getInstance();
		try {
			fingerprint2PgpKeyTrust = new HashMap<>();
			fullTrust = new HashSet<>();

			startTime = System.currentTimeMillis() / 1000;
			nextExpire = Long.MAX_VALUE;

			resetTrustRecords();

			final Set<PgpKeyFingerprint> ultimatelyTrustedKeyFingerprints = getUltimatelyTrustedKeyFingerprints();
			if (ultimatelyTrustedKeyFingerprints.isEmpty()) {
				logger.warn("updateTrustDb: There are no ultimately trusted keys!");
				return;
			}

			// mark all UTKs as used and fully_trusted and set validity to ultimate
			for (final PgpKeyFingerprint utkFpr : ultimatelyTrustedKeyFingerprints) {
				final PgpKey utk = pgpKeyRegistry.getPgpKey(utkFpr);
				if (utk == null) {
					logger.warn("public key of ultimately trusted key '{}' not found!", utkFpr.toHumanString());
					continue;
				}

				fullTrust.add(utkFpr);

				for (PgpUserId pgpUserId : utk.getPgpUserIds())
					updateValidity(pgpUserId, 0, TRUST_ULTIMATE, 0, 0);

				final long expireDate = getExpireTimestamp(utk.getPublicKey());
				if (expireDate >= startTime && expireDate < nextExpire)
					nextExpire = expireDate;
			}

			klist = ultimatelyTrustedKeyFingerprints;

			for (int depth = 0; depth < config.getMaxCertDepth(); ++depth) {
				final List<PgpKey> validatedKeys = validateKeyList();

				klist = new HashSet<>();
				for (PgpKey pgpKey : validatedKeys) {
					PgpKeyTrust pgpKeyTrust = getPgpKeyTrust(pgpKey);
					klist.add(pgpKey.getPgpKeyFingerprint());

					for (final PgpUserIdTrust pgpUserIdTrust : pgpKeyTrust.getPgpUserIdTrusts()) {
						final PgpUserId pgpUserId = pgpUserIdTrust.getPgpUserId();

						final int validity = pgpUserIdTrust.getValidity();
						updateValidity(pgpUserId, depth, validity,
								pgpUserIdTrust.getFullCount(), pgpUserIdTrust.getMarginalCount());

						if (validity >= TRUST_FULLY)
							fullTrust.add(pgpUserIdTrust.getPgpUserId().getPgpKey().getPgpKeyFingerprint());
					}

					final long expireDate = getExpireTimestamp(pgpKey.getPublicKey());
					if (expireDate >= startTime && expireDate < nextExpire)
						nextExpire = expireDate;
				}

				logger.debug("updateTrustDb: depth={} keys={}",
						depth, validatedKeys.size());
			}

			final Date nextExpireDate = new Date(nextExpire * 1000);
			trustDbIo.updateVersionRecord(nextExpireDate);

			trustDbIo.flush();

			logger.info("updateTrustDb: Next trust-db expiration date: {}", getDateFormatIso8601WithTime().format(nextExpireDate));
		} finally {
			fingerprint2PgpKeyTrust = null;
			klist = null;
			fullTrust = null;
		}
	}

	private long getExpireTimestamp(PGPPublicKey pk) {
		final long validSeconds = pk.getValidSeconds();
		if (validSeconds == 0)
			return Long.MAX_VALUE;

		final long result = (pk.getCreationTime().getTime() / 1000) + validSeconds;
		return result;
	}

	private List<PgpKey> validateKeyList() {
		final List<PgpKey> result = new ArrayList<>();
		final Set<PgpKeyFingerprint> signedPgpKeyFingerprints = new HashSet<>();
		for (PgpKeyFingerprint signingPgpKeyFingerprint : klist)
			signedPgpKeyFingerprints.addAll(pgpKeyRegistry.getPgpKeyFingerprintsSignedBy(signingPgpKeyFingerprint));

		signedPgpKeyFingerprints.removeAll(fullTrust); // no need to validate those that are already fully trusted

		for (final PgpKeyFingerprint pgpKeyFingerprint : signedPgpKeyFingerprints) {
			final PgpKey pgpKey = pgpKeyRegistry.getPgpKey(pgpKeyFingerprint);
			if (pgpKey == null) {
				logger.warn("key disappeared: fingerprint='{}'", pgpKeyFingerprint);
				continue;
			}
			result.add(pgpKey);
			validateKey(pgpKey);
		}
		return result;
	}

	private void validateKey(final PgpKey pgpKey) {
		assertNotNull("pgpKey", pgpKey);
		logger.debug("validateKey: {}", pgpKey);

		final Config config = Config.getInstance();
		final PgpKeyTrust pgpKeyTrust = getPgpKeyTrust(pgpKey);

		final boolean expired = isExpired(pgpKey.getPublicKey());
//		final boolean disabled = isDisabled(pgpKey.getPublicKey());
		final boolean revoked = pgpKey.getPublicKey().isRevoked();

		for (final PgpUserId pgpUserId : pgpKey.getPgpUserIds()) {
			final PgpUserIdTrust pgpUserIdTrust = pgpKeyTrust.getPgpUserIdTrust(pgpUserId);

			pgpUserIdTrust.setValidity(0); // TRUST_UNKNOWN = 0
			pgpUserIdTrust.setUltimateCount(0);
			pgpUserIdTrust.setFullCount(0);
			pgpUserIdTrust.setMarginalCount(0);

			if (expired)
				continue;

//			if (disabled)
//				continue;

			if (revoked)
				continue;

			for (PGPSignature certification : pgpKeyRegistry.getSignatures(pgpUserId)) {
				// It seems, the PGP trust model does not care about the certification level :-(
				// Any of the 3 DEFAULT, CASUAL, POSITIVE is as fine as the other -
				// there is no difference (at least according to my tests).
				if (certification.getSignatureType() != PGPSignature.DEFAULT_CERTIFICATION
						&& certification.getSignatureType() != PGPSignature.CASUAL_CERTIFICATION
						&& certification.getSignatureType() != PGPSignature.POSITIVE_CERTIFICATION)
					continue;

				PGPSignatureSubpacketVector hashedSubPackets = certification.getHashedSubPackets();
				if (hashedSubPackets != null) {
					if (hashedSubPackets.getKeyExpirationTime() != 0) {

					}
				}

				final PgpKey signingKey = pgpKeyRegistry.getPgpKey(new PgpKeyId(certification.getKeyID()));
				if (signingKey == null)
					continue;

				final int signingOwnerTrust = getOwnerTrust(signingKey.getPublicKey());
				if (signingKey.getPgpKeyId().equals(pgpKey.getPgpKeyId())
						&& signingOwnerTrust != TRUST_ULTIMATE) {
					// It's *not* our own key [*not* TRUST_ULTIMATE] - hence we ignore the self-signature.
					continue;
				}

				int signingValidity = getValidity(signingKey.getPublicKey()) & TRUST_MASK;
				if (signingValidity <= TRUST_MARGINAL) {
					// If the signingKey is trusted only marginally or less, we ignore the certification completely.
					// Only fully trusted keys are taken into account for transitive trust.
					continue;
				}

				// The owner-trust of the signing key is relevant.
				switch (signingOwnerTrust) {
					case TRUST_ULTIMATE:
						pgpUserIdTrust.incUltimateCount();
						break;
					case TRUST_FULLY:
						pgpUserIdTrust.incFullCount();
						break;
					case TRUST_MARGINAL:
						pgpUserIdTrust.incMarginalCount();
						break;
					default: // ignoring!
						break;
				}
			}

			if (pgpUserIdTrust.getUltimateCount() >= 1)
				pgpUserIdTrust.setValidity(TRUST_FULLY);
			else if (pgpUserIdTrust.getFullCount() >= config.getCompletesNeeded())
				pgpUserIdTrust.setValidity(TRUST_FULLY);
			else if (pgpUserIdTrust.getFullCount() + pgpUserIdTrust.getMarginalCount() >= config.getMarginalsNeeded())
				pgpUserIdTrust.setValidity(TRUST_FULLY);
			else if (pgpUserIdTrust.getFullCount() >= 1 || pgpUserIdTrust.getMarginalCount() >= 1)
				pgpUserIdTrust.setValidity(TRUST_MARGINAL);
		}
	}
}
