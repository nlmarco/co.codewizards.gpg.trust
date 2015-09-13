package co.codewizards.gpg.trust;

import static co.codewizards.gpg.trust.AssertUtil.*;
import static co.codewizards.gpg.trust.IoUtil.*;

import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TrustDbIo implements AutoCloseable, TrustRecordConst {
	private static final Logger logger = LoggerFactory.getLogger(TrustDbIo.class);

	private final LinkedHashSet<Long> cacheRecordNums = new LinkedHashSet<Long>();
	private final Map<Long, TrustRecord> cacheRecordNum2TrustRecord = new HashMap<>();

	private final File file;
	private final RandomAccessFile raf;
	private final FileLock fileLock;

	public TrustDbIo(final File file) throws TrustDbIoException {
		this.file = assertNotNull("file", file);
		try {
			this.raf = new RandomAccessFile(file, "rw"); // or better use rwd/rws? maybe manually calling sync is sufficient?!
			fileLock = raf.getChannel().lock();
		} catch (IOException x) {
			throw new TrustDbIoException(x);
		}
		getTrustRecord(0, TrustRecord.Version.class); // read the version immediately when opening the file
	}

	public void updateVersionRecord() throws TrustDbIoException {
		TrustRecord.Version version = getTrustRecord(0, TrustRecord.Version.class);
		assertNotNull("version", version);

		Config config = Config.getInstance();

		version.setCreated(new Date());
		version.setMarginals(config.getMarginalsNeeded());
		version.setCompletes(config.getCompletesNeeded());
		version.setCertDepth(config.getMaxCertDepth());
		version.setTrustModel(config.getTrustModel());
		version.setMinCertLevel(config.getMinCertLevel());

		putTrustRecord(version);
	}

	public TrustRecord getTrustRecord(final long recordNum) throws TrustDbIoException {
		return getTrustRecord(recordNum, TrustRecord.class);
	}

	public TrustRecord.Trust getTrustByPublicKey(PGPPublicKey pk) throws TrustDbIoException
	{
		final byte[] fingerprint = pk.getFingerprint();
		return getTrustByFingerprint(fingerprint);
	}

	/** Record number of the trust hashtable.  */
	private long trustHashRec = 0;

	protected long getTrustHashRec() {
		if (trustHashRec == 0) {
			TrustRecord.Version version = getTrustRecord(0, TrustRecord.Version.class);
			assertNotNull("version", version);

			trustHashRec = version.getTrustHashTbl();
			if (trustHashRec == 0) {
				createHashTable(0);
				trustHashRec = version.getTrustHashTbl();
			}
		}
		return trustHashRec;
	}

	/**
	 * Append a new empty hashtable to the trustdb.  TYPE gives the type
	 * of the hash table.  The only defined type is 0 for a trust hash.
	 * On return the hashtable has been created, written, the version
	 * record updated, and the data flushed to the disk.  On a fatal error
	 * the function terminates the process.
	 */
	private void createHashTable(int type) throws TrustDbIoException {
		TrustRecord.Version version = getTrustRecord(0, TrustRecord.Version.class);
		assertNotNull("version", version);

		long offset;
		long recnum;

		try {
			offset = raf.length();
			raf.seek(offset);
		} catch (IOException e) {
			throw new TrustDbIoException(e);
		}

		recnum = offset / TRUST_RECORD_LEN;
		if (recnum <= 0) // This is will never be the first record.
			throw new IllegalStateException("recnum <= 0");

		if (type == 0)
			version.setTrustHashTbl(recnum);

		// Now write the records making up the hash table.
		final int n = (256 + ITEMS_PER_HTBL_RECORD - 1) / ITEMS_PER_HTBL_RECORD;
		for (int i = 0; i < n; ++i, ++recnum) {
			TrustRecord.Trust trust = new TrustRecord.Trust();
			trust.recordNum = recnum;
			putTrustRecord(trust);
		}
		// Update the version record and flush.
		putTrustRecord(version);
		sync();
	}

	public TrustRecord.Trust getTrustByFingerprint(final byte[] fingerprint) throws TrustDbIoException {
		/* Locate the trust record using the hash table */
		TrustRecord rec = getTrustRecordViaHashTable(getTrustHashRec(), fingerprint, new TrustRecordMatcher() {
			@Override
			public boolean matches(final TrustRecord trustRecord) {
				if (! (trustRecord instanceof TrustRecord.Trust))
					return false;

				final TrustRecord.Trust trust = (TrustRecord.Trust) trustRecord;
				return Arrays.equals(trust.getFingerprint(), fingerprint);
			}
		});
		return (TrustRecord.Trust) rec;
	}

	private static interface TrustRecordMatcher {
		boolean matches(TrustRecord trustRecord);
	}

	// static gpg_error_t lookup_hashtable (ulong table, const byte *key, size_t keylen, int (*cmpfnc)(const void*, const TRUSTREC *), const void *cmpdata, TRUSTREC *rec )
	public TrustRecord getTrustRecordViaHashTable(long table, byte[] key, TrustRecordMatcher matcher) {
		long hashrec, item;
		int msb;
		int level = 0;

		hashrec = table;
		next_level: while (true) {
			msb = key[level] & 0xff;
			hashrec += msb / ITEMS_PER_HTBL_RECORD;
			TrustRecord.HashTbl hashTable = getTrustRecord(hashrec, TrustRecord.HashTbl.class);
			assertNotNull("hashTable", hashTable);

			item = hashTable.getItem(msb % ITEMS_PER_HTBL_RECORD);
			if (item == 0)
				return null; // not found!

			TrustRecord record = getTrustRecord(item);
			assertNotNull("record", record);

			if (record.getType() == TrustRecordType.HTBL) {
				hashrec = item;
				if (++level >= key.length)
					throw new TrustDbIoException("hashtable has invalid indirections");

				continue next_level;
			}

			if (record.getType() == TrustRecordType.HLST) {
				TrustRecord.HashLst hashList = (TrustRecord.HashLst) record;

				for (;;) {
					for (int i = 0; i < ITEMS_PER_HLST_RECORD; i++) {
						if (hashList.getRNum(i) != 0) {
							TrustRecord tmp = getTrustRecord(hashList.getRNum(i));
							if (tmp != null && matcher.matches(tmp))
								return tmp;
						}
					}

					if (hashList.getNext() != 0) {
						hashList = getTrustRecord(hashList.getNext(), TrustRecord.HashLst.class);
						assertNotNull("hashList", hashList);
					}
					else
						return null;
				}
			}

			if (matcher.matches(record))
				return record;
		}
	}

	public <T extends TrustRecord> T getTrustRecord(final long recordNum, Class<T> expectedTrustRecordClass) throws TrustDbIoException {
		assertNotNull("expectedTrustRecordClass", expectedTrustRecordClass);
		final TrustRecordType expectedType = expectedTrustRecordClass ==
				TrustRecord.class ? null : TrustRecordType.fromClass(expectedTrustRecordClass);

		TrustRecord record = getFromCache(recordNum);
		if (record == null) {
			try {
				raf.seek(recordNum * TRUST_RECORD_LEN);
			} catch (IOException x) {
				throw new TrustDbIoException(x);
			}

			final byte[] buf = new byte[TRUST_RECORD_LEN];
			try {
				raf.readFully(buf);
			} catch (EOFException x) {
				return null;
			} catch (IOException x) {
				throw new TrustDbIoException(x);
			}

			int bufIdx = 0;

			final TrustRecordType type = TrustRecordType.fromId((short) (buf[bufIdx++] & 0xFF));
			if (expectedType != null && ! expectedType.equals(type))
				throw new IllegalStateException(String.format("expectedType != foundType :: %s != %s", expectedType, type));

			++bufIdx; // Skip reserved byte.

			switch (type) {
			case UNUSED:  // unused (free) record
				record = new TrustRecord.Unused();
				break;
			case VERSION: // version record
				final TrustRecord.Version version = new TrustRecord.Version();
				record = version;

				--bufIdx; // undo skip reserved byte, because this does not apply to VERSION record.
				if (buf[bufIdx++] != 'g'
						|| buf[bufIdx++] != 'p'
						|| buf[bufIdx++] != 'g')
					throw new TrustDbIoException(String.format("Not a trustdb file: %s", file.getAbsolutePath()));

				version.version  = (short) (buf[bufIdx++] & 0xFF);
				version.marginals = (short) (buf[bufIdx++] & 0xFF);
				version.completes = (short) (buf[bufIdx++] & 0xFF);
				version.certDepth = (short) (buf[bufIdx++] & 0xFF);
				version.trustModel = (short) (buf[bufIdx++] & 0xFF);
				version.minCertLevel = (short) (buf[bufIdx++] & 0xFF);

				bufIdx += 2; // no idea why, but we have to skip 2 bytes
				version.created = new Date(1000L * (bytesToInt(buf, bufIdx) & 0xFFFFFFFFL)); bufIdx += 4;
				version.nextCheck = new Date(1000L * (bytesToInt(buf, bufIdx) & 0xFFFFFFFFL)); bufIdx += 4;
				bufIdx += 4; // no idea why, but we have to skip 4 bytes
				bufIdx += 4; // no idea why, but we have to skip 4 bytes
				version.firstFree = bytesToInt(buf, bufIdx) & 0xFFFFFFFFL; bufIdx += 4;
				bufIdx += 4; // no idea why, but we have to skip 4 bytes
				version.trustHashTbl = bytesToInt(buf, bufIdx) & 0xFFFFFFFFL; bufIdx += 4;

				if (version.version != 3)
					throw new TrustDbIoException(String.format("Wrong version number (3 expected, but %d found): %s", version.version, file.getAbsolutePath()));
				break;
			case FREE:
				final TrustRecord.Free free = new TrustRecord.Free();
				record = free;
				free.next = bytesToInt(buf, bufIdx) & 0xFFFFFFFFL; bufIdx += 4;
				break;
			case HTBL:
				final TrustRecord.HashTbl hashTbl = new TrustRecord.HashTbl();
				record = hashTbl;
				for (int i = 0; i < ITEMS_PER_HTBL_RECORD; ++i) {
					hashTbl.item[i] = bytesToInt(buf, bufIdx) & 0xFFFFFFFFL; bufIdx += 4;
				}
				break;
			case HLST:
				final TrustRecord.HashLst hashLst = new TrustRecord.HashLst();
				record = hashLst;
				hashLst.next = bytesToInt(buf, bufIdx) & 0xFFFFFFFFL; bufIdx += 4;
				for (int i = 0; i < ITEMS_PER_HLST_RECORD; ++i) {
					hashLst.rnum[i] = bytesToInt(buf, bufIdx) & 0xFFFFFFFFL; bufIdx += 4;
				}
				break;
			case TRUST:
				final TrustRecord.Trust trust = new TrustRecord.Trust();
				record = trust;
				System.arraycopy(buf, bufIdx, trust.fingerprint, 0, 20); bufIdx += 20;
				trust.ownerTrust = (short) (buf[bufIdx++] & 0xFF);
				trust.depth = (short) (buf[bufIdx++] & 0xFF);
				trust.minOwnerTrust = (short) (buf[bufIdx++] & 0xFF);
				++bufIdx; // no idea why, but we have to skip 1 byte
				trust.validList = bytesToInt(buf, bufIdx) & 0xFFFFFFFFL; bufIdx += 4;
				break;
			case VALID:
				final TrustRecord.Valid valid = new TrustRecord.Valid();
				record = valid;
				System.arraycopy(buf, bufIdx, valid.nameHash, 0, 20); bufIdx += 20;
				valid.validity = (short) (buf[bufIdx++] & 0xFF);
				valid.next = bytesToInt(buf, bufIdx) & 0xFFFFFFFFL; bufIdx += 4;
				valid.fullCount = (short) (buf[bufIdx++] & 0xFF);
				valid.marginalCount = (short) (buf[bufIdx++] & 0xFF);
				break;
			default:
				throw new IllegalArgumentException("Unexpected TrustRecordType: " + type);
			}
			record.recordNum = recordNum;
			putToCache(record);
		}
		else {
			if (expectedType != null && ! expectedType.equals(record.getType()))
				throw new IllegalStateException(String.format("expectedType != foundType :: %s != %s", expectedType, record.getType()));
		}

		return expectedTrustRecordClass.cast(record);
	}

	public void putTrustRecord(final TrustRecord record) throws TrustDbIoException {
		assertNotNull("record", record);

		int bufIdx = 0;
		final byte[] buf = new byte[TRUST_RECORD_LEN];

		buf[bufIdx++] = (byte) record.getType().getId();
		++bufIdx; // Skip reserved byte.

		switch (record.getType()) {
		case UNUSED:  // unused (free) record
			break;
		case VERSION: // version record
			final TrustRecord.Version version = (TrustRecord.Version) record;

			--bufIdx; // undo skip reserved byte, because this does not apply to VERSION record.
			buf[bufIdx++] = 'g';
			buf[bufIdx++] = 'p';
			buf[bufIdx++] = 'g';

			buf[bufIdx++] = (byte) version.version;
			buf[bufIdx++] = (byte) version.marginals;
			buf[bufIdx++] = (byte) version.completes;
			buf[bufIdx++] = (byte) version.certDepth;
			buf[bufIdx++] = (byte) version.trustModel;
			buf[bufIdx++] = (byte) version.minCertLevel;

			bufIdx += 2; // no idea why, but we have to skip 2 bytes

			intToBytes((int) (version.created.getTime() / 1000L), buf, bufIdx); bufIdx += 4;
			intToBytes((int) (version.nextCheck.getTime() / 1000L), buf, bufIdx); bufIdx += 4;
			bufIdx += 4; // no idea why, but we have to skip 4 bytes
			bufIdx += 4; // no idea why, but we have to skip 4 bytes
			intToBytes((int) version.firstFree, buf, bufIdx); bufIdx += 4;
			bufIdx += 4; // no idea why, but we have to skip 4 bytes
			intToBytes((int) version.trustHashTbl, buf, bufIdx); bufIdx += 4;

			if (version.version != 3)
				throw new TrustDbIoException(String.format("Wrong version number (3 expected, but %d found): %s", version.version, file.getAbsolutePath()));
			break;
		case FREE:
			final TrustRecord.Free free = (TrustRecord.Free) record;
			intToBytes((int) free.next, buf, bufIdx); bufIdx += 4;
			break;
		case HTBL:
			final TrustRecord.HashTbl hashTbl = (TrustRecord.HashTbl) record;
			for (int i = 0; i < ITEMS_PER_HTBL_RECORD; ++i) {
				intToBytes((int) hashTbl.item[i], buf, bufIdx); bufIdx += 4;
			}
			break;
		case HLST:
			final TrustRecord.HashLst hashLst = (TrustRecord.HashLst) record;
			intToBytes((int) hashLst.next, buf, bufIdx); bufIdx += 4;
			for (int i = 0; i < ITEMS_PER_HLST_RECORD; ++i) {
				intToBytes((int) hashLst.rnum[i], buf, bufIdx); bufIdx += 4;
			}
			break;
		case TRUST:
			final TrustRecord.Trust trust = (TrustRecord.Trust) record;
			System.arraycopy(trust.fingerprint, 0, buf, bufIdx, 20); bufIdx += 20;
			buf[bufIdx++] = (byte) trust.ownerTrust;
			buf[bufIdx++] = (byte) trust.depth;
			buf[bufIdx++] = (byte) trust.minOwnerTrust;
			++bufIdx; // no idea why, but we have to skip 1 byte
			intToBytes((int) trust.validList, buf, bufIdx); bufIdx += 4;
			break;
		case VALID:
			final TrustRecord.Valid valid = (TrustRecord.Valid) record;
			System.arraycopy(valid.nameHash, 0, buf, bufIdx, 20); bufIdx += 20;
			buf[bufIdx++] = (byte) valid.validity;
			intToBytes((int) valid.next, buf, bufIdx); bufIdx += 4;
			buf[bufIdx++] = (byte) valid.fullCount;
			buf[bufIdx++] = (byte) valid.marginalCount;
			break;
		default:
			throw new IllegalArgumentException("Unexpected TrustRecordType: " + record.getType());
		}

		try {
			raf.write(buf);
		} catch (IOException e) {
			throw new TrustDbIoException(e);
		}
		putToCache(record);
	}

	private TrustRecord getFromCache(long recordNum) {
		return cacheRecordNum2TrustRecord.get(recordNum);
	}

	private void putToCache(TrustRecord trustRecord) {
		assertNotNull("trustRecord", trustRecord);
		final long recordNum = trustRecord.getRecordNum();

		if (cacheRecordNum2TrustRecord.containsKey(recordNum))
			cacheRecordNums.remove(recordNum);

		while (cacheRecordNums.size() + 1 > MAX_CACHE_SIZE) {
			final Long oldestRecordNum = cacheRecordNums.iterator().next();
			cacheRecordNums.remove(oldestRecordNum);
			cacheRecordNum2TrustRecord.remove(oldestRecordNum);
		}

		cacheRecordNum2TrustRecord.put(recordNum, trustRecord);
		cacheRecordNums.add(recordNum);
	}

	public void sync() throws TrustDbIoException {
		try {
			raf.getFD().sync();
		} catch (IOException e) {
			throw new TrustDbIoException(e);
		}
	}

	@Override
	public void close() throws TrustDbIoException {
		try {
			fileLock.release();
			raf.close();
		} catch (IOException e) {
			throw new TrustDbIoException(e);
		}
	}
}
