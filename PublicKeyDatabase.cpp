#include "PublicKeyDatabase.h"
#include "BitcoinAddress.h"
#include "FileInterface.h"
#include "logging.h"

#include "CRC32.h"

#include <stdio.h>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <assert.h>
#include <time.h>

#define ONE_BTC 100000000
#define ONE_MBTC (ONE_BTC/1000)


#ifdef _MSC_VER
#pragma warning(disable:4100 4996 4189)
#endif

namespace PUBLIC_KEY_DATABASE
{
	typedef std::vector< uint64_t > TransactionVector;

	// A 256 bit hash
	class Hash256
	{
	public:
		Hash256(void)
		{
			mWord0 = 0;
			mWord1 = 0;
			mWord2 = 0;
			mWord3 = 0;
		}

		Hash256(const Hash256 &h)
		{
			mWord0 = h.mWord0;
			mWord1 = h.mWord1;
			mWord2 = h.mWord2;
			mWord3 = h.mWord3;
		}

		inline Hash256(const uint8_t *src)
		{
			mWord0 = *(const uint64_t *)(src);
			mWord1 = *(const uint64_t *)(src + 8);
			mWord2 = *(const uint64_t *)(src + 16);
			mWord3 = *(const uint64_t *)(src + 24);
		}

		inline uint32_t getHash(void) const
		{
			const uint32_t *h = (const uint32_t *)&mWord0;
			return h[0] ^ h[1] ^ h[2] ^ h[3] ^ h[4] ^ h[5] ^ h[6] ^ h[7];
		}

		inline bool operator==(const Hash256 &h) const
		{
			return mWord0 == h.mWord0 && mWord1 == h.mWord1 && mWord2 == h.mWord2 && mWord3 == h.mWord3;
		}


		uint64_t	mWord0;
		uint64_t	mWord1;
		uint64_t	mWord2;
		uint64_t	mWord3;
	};

	class PublicKeyData
	{
	public:
		bool operator==(const PublicKeyData &other) const
		{
			return memcmp(address, other.address, sizeof(address)) == 0;
		}

		uint8_t address[25];
	};


	class PublicKey : public PublicKeyData
	{
	public:
		PublicKey(void)
		{
		}

		PublicKey(const PublicKeyData &h) : PublicKeyData(h)
		{
			mCRC = CRC32(address, sizeof(address), sizeof(address));
		}

		// Here the == operator is used to see if the hash values match
		bool operator==(const PublicKey &other) const
		{
			if (mCRC == other.mCRC) // if they have the same CRC value...
			{
				const PublicKeyData &a = *this;
				const PublicKeyData &b = other;
				return a == b;
			}
			return false;
		}

		uint32_t getHash(void) const
		{
			return mCRC;
		}
		uint32_t	mIndex;
		uint32_t	mCRC;
	};

	// Data we would like to accumulate
	// First, is it a spend or a receive transaction
	// How much value is involved
	// What is the timestamp
	// Must be exact multiple of 16 bytes
	class PublicKeyTransaction
	{
	public:
		PublicKeyTransaction(void) : mTransactionOffset(0)
			, mValue(0)
			, mTimeStamp(0)
			, mSpend(false)
			, mCoinbase(false)
			, mChange(false)
		{
		}
		uint64_t	mTransactionOffset;		//  8 : The file offset location to the full transaction details
		uint64_t	mValue;					// 16 : How much value is in this spend/receive transaction
		uint32_t	mTimeStamp;				// 20 : Time stamp for this transaction
		bool		mSpend : 1;				// 24 : is it a spend transaction?
		bool		mCoinbase : 1;			// is it a coinbase transaction
		bool		mChange : 1;			// Whether or not this receive was change (came from ourselves)
		uint64_t	mPadding;				// 8 bytes of padding
	};

	typedef std::vector< PublicKeyTransaction > PublicKeyTransactionVector;

	// This class represents the collection of all transactions associated with a particular public key
	class PublicKeyRecord
	{
	public:
		void save(FILE_INTERFACE *fph)
		{
			fi_fwrite(&mKeyType, sizeof(mKeyType), 1, fph);
			fi_fwrite(&mIndex, sizeof(mIndex), 1, fph);
			uint32_t count = uint32_t(mTransactions.size());
			fi_fwrite(&count, sizeof(count), 1, fph);
			uint32_t padding = 0x0A0B0C0D;
			fi_fwrite(&padding, sizeof(count), 1, fph);
			if (count)
			{
				PublicKeyTransaction *p = &mTransactions[0];
				fi_fwrite(p, sizeof(PublicKeyTransaction)*count, 1, fph);
			}
		}
		BlockChain::KeyType			mKeyType;			// What type of bitcoin key is this?  Standard, MultiSig, Pay2Hash, Stealth?
		uint32_t					mIndex;				// The array index for this public key (needed after pointer sorting)
		PublicKeyTransactionVector	mTransactions;		// all transactions in chronological order relative to this public key
	};

	// For performance and memory reasons we access the PublicKeyRecords from a memory mapped file; which refers to the copy
	// saved to disk rather than the one used during the build phase
	// Must match exactly the layout produced by the 'save' method in PublicKeyRecord
	class PublicKeyRecordFile
	{
	public:

		uint64_t getBalance(void) const
		{
			uint64_t ret = 0;
			for (uint32_t i = 0; i < mCount; i++)
			{
				const PublicKeyTransaction &t = mTransactions[i];
				if (t.mSpend)
				{
					ret -= t.mValue;
				}
				else
				{
					ret += t.mValue;
				}
			}
			return ret;
		}

		uint64_t getTotalSend(void) const
		{
			uint64_t ret = 0;
			for (uint32_t i = 0; i < mCount; i++)
			{
				const PublicKeyTransaction &t = mTransactions[i];
				if (t.mSpend)
				{
					ret += t.mValue;
				}
			}
			return ret;
		}

		uint64_t getTotalReceive(void) const
		{
			uint64_t ret = 0;
			for (uint32_t i = 0; i < mCount; i++)
			{
				const PublicKeyTransaction &t = mTransactions[i];
				if (!t.mSpend)
				{
					ret += t.mValue;
				}
			}
			return ret;
		}

		uint32_t getLastSendTime(void) const
		{
			uint32_t ret = 0;

			uint32_t count = mCount;
			if (count)
			{
				uint32_t index = count - 1;
				for (uint32_t i = 0; i < count; i++, index--)
				{
					const PublicKeyTransaction &t = mTransactions[index];
					if (t.mSpend)
					{
						ret = t.mTimeStamp;
						break;
					}
				}
			}
			return ret;
		}


		uint32_t getLastReceiveTime(void) const
		{
			uint32_t ret = 0;

			uint32_t count = mCount;
			if (count)
			{
				uint32_t index = count - 1;
				for (uint32_t i = 0; i < count; i++, index--)
				{
					const PublicKeyTransaction &t = mTransactions[index];
					if (!t.mSpend)
					{
						ret = t.mTimeStamp;
						break;
					}
				}
			}
			return ret;
		}

		BlockChain::KeyType			mKeyType;			// What type of bitcoin key is this?  Standard, MultiSig, Pay2Hash, Stealth?
		uint32_t					mIndex;				// Array index for public key
		uint32_t					mCount;
		uint32_t					mPadding;			// Must be here because the PublicKeyTransaction is going to be 16 byte aligned!
		PublicKeyTransaction		mTransactions[1];	// This is a bit of a fake; we are accessing this via a memory mapped file so there will be 'mCount' number of actual transactions
	};

	class TransactionHash : public Hash256
	{
	public:
		TransactionHash(void)
		{
		}

		TransactionHash(const Hash256 &h) : Hash256(h)
		{
		}

		// Here the == operator is used to see if the hash values match
		bool operator==(const TransactionHash &other) const
		{
			const Hash256 &a = *this;
			const Hash256 &b = other;
			return a == b;
		}

		uint64_t			mFileOffset;	// The location in the file for this transaction
	};

	class TransactionOutput
	{
	public:
		TransactionOutput(void)
		{

		}

		TransactionOutput(const BlockChain::BlockOutput &bo,uint32_t addressIndex)
		{
			mValue		= bo.value;
			mIndex		= addressIndex;
			mKeyType	= bo.keyType;
		}

		TransactionOutput(FILE_INTERFACE *fph)
		{
			fi_fread(&mValue, sizeof(mValue), 1, fph);
			fi_fread(&mIndex, sizeof(mIndex), 1, fph);
			fi_fread(&mKeyType, sizeof(mKeyType), 1, fph);
		}


		void save(FILE_INTERFACE *fph)
		{
			fi_fwrite(&mValue, sizeof(mValue), 1, fph);
			fi_fwrite(&mIndex, sizeof(mIndex), 1, fph);
			fi_fwrite(&mKeyType, sizeof(mKeyType), 1, fph);
		}

		void echo(void)
		{

		}

		uint64_t					mValue;		// The value of the output
		uint32_t					mIndex;		// The array index for this public key (stored in a separate table)
		BlockChain::KeyType			mKeyType;	// type of key
	};

	class TransactionInput
	{
	public:
		TransactionInput(void)
		{

		}
		TransactionInput(const BlockChain::BlockInput &bi, uint64_t fileOffset)
		{
			mTransactionFileOffset	= fileOffset;
			mTransactionIndex		= bi.transactionIndex;
			mInputValue				= bi.inputValue;
		}

		TransactionInput(FILE_INTERFACE *fph)
		{
			fi_fread(&mTransactionFileOffset, sizeof(mTransactionFileOffset), 1, fph);
			fi_fread(&mTransactionIndex, sizeof(mTransactionIndex), 1, fph);
			fi_fread(&mInputValue, sizeof(mInputValue), 1, fph);
		}

		void save(FILE_INTERFACE *fph)
		{
			fi_fwrite(&mTransactionFileOffset, sizeof(mTransactionFileOffset), 1, fph);
			fi_fwrite(&mTransactionIndex, sizeof(mTransactionIndex), 1, fph);
			fi_fwrite(&mInputValue, sizeof(mInputValue), 1, fph);
		}

		void echo(void)
		{

		}

		uint64_t	mTransactionFileOffset;			// Which transaction this input refers to (0 means coinbase)
		uint32_t	mTransactionIndex;				// Which output forms this input
		uint64_t	mInputValue;					// The input value
	};

	typedef std::vector< TransactionInput > TransactionInputVector;
	typedef std::vector< TransactionOutput > TransactionOutputVector;

	// Temporarily holds the data representing a transaction
	class Transaction
	{
	public:
		Transaction(void)
		{

		}

		Transaction(const BlockChain::BlockTransaction &t,uint32_t transactionTime,uint32_t blockNumber) 
		{
			memcpy(mTransactionHash, t.transactionHash, sizeof(mTransactionHash));
			mTransactionVersionNumber = t.transactionVersionNumber;
			mLockTime = t.lockTime;
			mTransactionTime = transactionTime;
			mBlockNumber = blockNumber;
		}


		bool read(FILE_INTERFACE *fph)
		{
			bool ret = true;

			mInputs.clear();
			mOutputs.clear();
			size_t r = fi_fread(mTransactionHash, sizeof(mTransactionHash), 1, fph);		// Write out the transaction hash
			if (r != 1)
			{
				ret = false;
			}
			else
			{
				fi_fread(&mBlockNumber, sizeof(mBlockNumber), 1, fph);		// Write out the transaction hash
				fi_fread(&mTransactionVersionNumber, sizeof(mTransactionVersionNumber), 1, fph);	// Write out the transaction version number
				fi_fread(&mTransactionTime, sizeof(mTransactionTime), 1, fph);		// Write out the block-time of this transaction.
				fi_fread(&mLockTime, sizeof(mLockTime), 1, fph);						// Write out the lock-time of this transaction.
				uint32_t count;
				fi_fread(&count, sizeof(count), 1, fph);
				mInputs.reserve(count);
				for (uint32_t i = 0; i < count; i++)
				{
					TransactionInput ti(fph);
					mInputs.push_back(ti);
				}
				fi_fread(&count, sizeof(count), 1, fph);
				mOutputs.reserve(count);
				for (uint32_t i = 0; i < count; i++)
				{
					TransactionOutput to(fph);
					mOutputs.push_back(to);
				}
			}


			return ret;
		}

		void save(FILE_INTERFACE *fph)
		{
			fi_fwrite(mTransactionHash, sizeof(mTransactionHash), 1, fph);		// Write out the transaction hash
			fi_fwrite(&mBlockNumber, sizeof(mBlockNumber), 1, fph);		// Write out the transaction hash
			fi_fwrite(&mTransactionVersionNumber, sizeof(mTransactionVersionNumber), 1, fph);	// Write out the transaction version number
			fi_fwrite(&mTransactionTime, sizeof(mTransactionTime), 1, fph);		// Write out the block-time of this transaction.
			fi_fwrite(&mLockTime, sizeof(mLockTime), 1, fph);						// Write out the lock-time of this transaction.
			uint32_t count = uint32_t(mInputs.size());							// Write out the number of transaction inputs
			fi_fwrite(&count, sizeof(count), 1, fph);
			for (uint32_t i = 0; i < count; i++)
			{
				mInputs[i].save(fph);	// Save each input
			}
			count = uint32_t(mOutputs.size());			// Write out the number of transaction outputs
			fi_fwrite(&count, sizeof(count), 1, fph);		
			for (uint32_t i = 0; i < count; i++)
			{
				mOutputs[i].save(fph);	// Write out each output
			}
		}

		void addInput(const BlockChain::BlockInput &bi, uint64_t fileOffset)
		{
			TransactionInput ti(bi, fileOffset);
			mInputs.push_back(ti);
		}

		void addOutput(const BlockChain::BlockOutput &bo,uint32_t addressIndex)
		{
			TransactionOutput to(bo,addressIndex);
			mOutputs.push_back(to);
		}

		void echo(void)
		{
			logMessage("===============================================================================================================================\r\n");
			logMessage("TransactionHash: ");
			printReverseHash(mTransactionHash);
			logMessage("\r\n");
			logMessage("BlockNumber: %d\r\n", mBlockNumber);
			logMessage("TransactionVersionNumber: %d\r\n", mTransactionVersionNumber);
			logMessage("TransactionTime: %s\r\n", getDateString(time_t(mTransactionTime)));
			logMessage("InputCount: %d\r\n", mInputs.size());
			for (size_t i = 0; i < mInputs.size(); i++)
			{
				mInputs[i].echo();
			}
			logMessage("OutputCount: %d\r\n", mOutputs.size());
			for (size_t i = 0; i < mOutputs.size(); i++)
			{
				mOutputs[i].echo();
			}
			logMessage("===============================================================================================================================\r\n");
			logMessage("\r\n");
		}

		uint8_t						mTransactionHash[32];				// The transaction hash
		uint32_t					mBlockNumber;						// Which block this transaction resides in
		uint32_t					mTransactionVersionNumber;			// The transaction version number
		uint32_t					mTransactionTime;					// The time of the transaction (approximate, based on the block time stamp this transaction was contained in)
		uint32_t					mLockTime;							// The lock time
		TransactionInputVector		mInputs;							// The total number of inputs in the transaction
		TransactionOutputVector		mOutputs;							// The total number of outputs in the transaction
	};


} // end of PUBLIC_KEY_DATABASE namespace

// A template to compute the hash value for a BlockHeader
namespace std
{
	template <>
	struct hash<PUBLIC_KEY_DATABASE::PublicKey>
	{
		std::size_t operator()(const PUBLIC_KEY_DATABASE::PublicKey &k) const
		{
			return std::size_t(k.getHash());
		}
	};
	template <>
	struct hash<PUBLIC_KEY_DATABASE::TransactionHash>
	{
		std::size_t operator()(const PUBLIC_KEY_DATABASE::TransactionHash &k) const
		{
			return std::size_t(k.getHash());
		}
	};
}

namespace PUBLIC_KEY_DATABASE
{

#define TRANSACTION_FILE_NAME			"TransactionFile.bin"
#define PUBLIC_KEY_FILE_NAME			"PublicKeys.bin"
#define PUBLIC_KEY_RECORDS_FILE_NAME	"PublicKeyRecords.bin"

	typedef std::unordered_set< PublicKey >			PublicKeySet;			// The unordered set of all public keys
	typedef std::unordered_set< TransactionHash >	TransactionHashSet;		// The unordered set of all transactions; only contains the file seek offset

	const char *magicID = "0123456789ABCDE";

	class PublicKeyDatabaseImpl : public PublicKeyDatabase
	{
	public:
		PublicKeyDatabaseImpl(bool analyze) : mPublicKeyCount(0)
			, mTransactionFile(nullptr)
			, mAnalyze(analyze)
			, mAddresses(nullptr)
			, mAddressFile(nullptr)
			, mPublicKeyRecordFile(nullptr)
			, mPublicKeyRecordBaseAddress(nullptr)
			, mPublicKeyRecordOffsets(nullptr)
			, mPublicKeyRecordSorted(nullptr)
		{
			if (analyze)
			{
				openTransactionsFile();
				loadPublicKeyFile();
				loadPublicKeyRecordsFile();
			}
			else
			{
				mTransactionFile = fi_fopen(TRANSACTION_FILE_NAME, "wb",nullptr,0,false);
				if (mTransactionFile)
				{
					size_t slen = strlen(magicID);
					fi_fwrite(magicID, slen + 1, 1, mTransactionFile);
					fi_fflush(mTransactionFile);
				}
				else
				{
					logMessage("Failed to open file '%s' for write access.\r\n", TRANSACTION_FILE_NAME);
				}
			}
		}

		virtual ~PublicKeyDatabaseImpl(void)
		{
			if (mTransactionFile)
			{
				fi_fclose(mTransactionFile);
			}
			if (mPublicKeyRecordFile)
			{
				fi_fclose(mPublicKeyRecordFile);
			}
			if (mAddressFile)
			{
				fi_fclose(mAddressFile);
			}
		}

		virtual void addBlock(const BlockChain::Block *b) override final
		{
			if (!mTransactionFile || mAnalyze )
			{
				return;
			}

			for (uint32_t i = 0; i < b->transactionCount; i++)
			{
				uint64_t fileOffset = uint64_t(fi_ftell(mTransactionFile)); // the file offset for this transaction data
				const BlockChain::BlockTransaction &bt = b->transactions[i];

				Transaction t(bt,b->timeStamp,b->blockIndex);

				for (uint32_t i = 0; i < bt.inputCount; i++)
				{
					const BlockChain::BlockInput &bi = bt.inputs[i];
					Hash256 h(bi.transactionHash);
					TransactionHash th(h);
					TransactionHashSet::iterator found = mTransactions.find(th);
					uint64_t fileOffset = 0;
					if (found == mTransactions.end())
					{
						if (bi.transactionIndex != 0xFFFFFFFF) // If it is not a coinbase transaction, then assert
						{
							assert(0); // we should always be able to find the previous transaction!
						}
					}
					else
					{
						fileOffset = (*found).mFileOffset;
					}
					t.addInput(bi, fileOffset);
				}

				for (uint32_t i = 0; i < bt.outputCount; i++)
				{
					const BlockChain::BlockOutput &bo = bt.outputs[i];
					uint32_t addressIndex = getPublicKeyIndex(bo.asciiAddress);
					t.addOutput(bo,addressIndex);
				}

				t.save(mTransactionFile);
				Hash256 h(bt.transactionHash);
				TransactionHash th(h);
				th.mFileOffset = fileOffset;
				mTransactions.insert(th);	// Add it to the transaction hash table; so we can convert from a transaction hash to a file offset quickly and efficiently
			}

			fi_fflush(mTransactionFile);
		}

		// Once all of the blocks have been processed and transactions accumulated, we now
		// can build the public key database; this collates all transaction inputs and outupts
		// relative to each bitcoin address.
		// The purpose of this is so that we can later use this pre-processed database to perform
		// relatively high speed queries against the blockchain.  Most of the interesting data we want to 
		// collect is relative to public key addresses
		virtual void buildPublicKeyDatabase(void) override final
		{
			if (!mAnalyze)
			{
				savePublicKeyFile();
				mTransactionFile = nullptr;
				mTransactions.clear();		// We no longer need this hash-set of transaction hashes since we have rebased the data based the data based on transaction offset into the datafile
				mPublicKeys.clear();		// We no longer needs this hash set, so free up the memory
				mAnalyze = true;
				openTransactionsFile();
				loadPublicKeyFile();
			}
			PublicKeyRecord *records = new PublicKeyRecord[mPublicKeyCount];
			for (uint32_t i = 0; i < mPublicKeyCount; i++)
			{
				records[i].mIndex = i; // assign the array index
			}
			logMessage("Building PublicKey records.\r\n");
			uint32_t transactionCount = 0;
			uint64_t transactionOffset = uint64_t(fi_ftell(mTransactionFile));
			Transaction t;
			while (readTransaction(t, transactionOffset))
			{
				transactionCount++;
				if ((transactionCount % 10000) == 0)
				{
					logMessage("Processing transaction %s\r\n", formatNumber(transactionCount));
				}
				uint64_t toffset = transactionOffset; // the base transaction offset
				transactionOffset = uint64_t(fi_ftell(mTransactionFile));
				processTransaction(t,toffset,records);
				// do stuff here...
			}
			logMessage("Public Key Records built.\r\n");
			savePublicKeyRecords(records); // save the records to disk!
			logMessage("Finished saving public records, now deleting them.\r\n");
			delete[]records;
			logMessage("Public record deletion now complete.\r\n");
		}

		// Process all of the inputs and outputs in this transaction and correlate them with the records
		// for each corresponding public key
		void processTransaction(const Transaction &t,uint64_t transactionOffset,PublicKeyRecord *records)
		{
			bool hasCoinBase = false;

			for (auto i = t.mInputs.begin(); i != t.mInputs.end(); ++i)
			{
				const TransactionInput &ti = (*i);
				if (ti.mTransactionIndex != 0xFFFFFFFF) // if it is not a coinbase input...
				{
					Transaction inputTransaction;
					readTransaction(inputTransaction, ti.mTransactionFileOffset);
					assert(ti.mTransactionIndex < inputTransaction.mOutputs.size());
					TransactionOutput &to = inputTransaction.mOutputs[ti.mTransactionIndex];
					if (to.mIndex < mPublicKeyCount)
					{
						PublicKeyRecord &record = records[to.mIndex]; // ok...let's get the record
						PublicKeyTransaction pt;
						pt.mCoinbase = false;
						pt.mSpend = true;	// we are spending a previous output here...
						pt.mTimeStamp = t.mTransactionTime;
						pt.mTransactionOffset = transactionOffset;
						pt.mValue = to.mValue;
						record.mTransactions.push_back(pt);
					}
					else
					{
						logMessage("WARNING! Encountered index to public key #%s but the maximum number of public keys we have is %s\r\n", formatNumber(to.mIndex), formatNumber(mPublicKeyCount));
					}
				}
				else
				{
					hasCoinBase = true;
				}
			}

			for (auto i = t.mOutputs.begin(); i != t.mOutputs.end(); ++i)
			{
				const TransactionOutput &to = (*i);
				PublicKeyTransaction pt;
				pt.mCoinbase = hasCoinBase;
				hasCoinBase = false;
				pt.mSpend = false;
				pt.mTimeStamp = t.mTransactionTime;
				pt.mTransactionOffset = transactionOffset;
				pt.mValue = to.mValue;

				PublicKeyRecord &record = records[to.mIndex]; // ok...let's get the record
				if (to.mIndex < mPublicKeyCount)
				{
					record.mKeyType = to.mKeyType;

					// see if any of the transaction inputs is this output, in which case this gets flagged as 'change'
					for (auto i = t.mInputs.begin(); i != t.mInputs.end(); ++i)
					{
						const TransactionInput &ti = (*i);
						if (ti.mTransactionIndex != 0xFFFFFFFF) // if it is not a coinbase input...
						{
							Transaction inputTransaction;
							readTransaction(inputTransaction, ti.mTransactionFileOffset);
							assert(ti.mTransactionIndex < inputTransaction.mOutputs.size());
							TransactionOutput &pto = inputTransaction.mOutputs[ti.mTransactionIndex];
							if (pto.mIndex == to.mIndex)
							{
								pt.mChange = true;
								break;
							}
						}
					}
					record.mTransactions.push_back(pt);
				}
				else
				{
					logMessage("WARNING! Encountered index to public key #%s but the maximum number of public keys we have is %s\r\n", formatNumber(to.mIndex), formatNumber(mPublicKeyCount));
				}
			}
		}

		// Logically 'reads' a Transaction; but since this is via a memory mapped file this will 
		// just be memory copies
		bool readTransaction(Transaction &t, uint64_t transactionOffset)
		{
			bool ret = false;

			{
				fi_fseek(mTransactionFile, size_t(transactionOffset), SEEK_SET);
				uint64_t actual = uint64_t(fi_ftell(mTransactionFile));
				if (actual == transactionOffset)
				{
					ret = t.read(mTransactionFile); // read this transaction 
				}
			}

			return ret;
		}

		// Opens a previously saved transactions file (as a memory mapped file so we don't use up system memory)
		bool openTransactionsFile(void)
		{
			if (mTransactionFile) return false;
			mTransactionFile = fi_fopen(TRANSACTION_FILE_NAME, "rb",nullptr,0,true);
			if (mTransactionFile == nullptr)
			{
				logMessage("Failed to open transaction file '%s' for read access.\r\n", TRANSACTION_FILE_NAME);
				return false;
			}
			size_t slen = strlen(magicID);
			char *temp = new char[slen + 1];
			size_t r = fi_fread(temp, slen + 1, 1, mTransactionFile);
			bool ret = false;
			if (r == 1)
			{
				if (strcmp(temp, magicID) == 0)
				{
					ret = true;
					logMessage("Successfully opened the transaction file '%s' for read access.\r\n", TRANSACTION_FILE_NAME);
				}
				else
				{
					logMessage("Not a valid transaction invalid header block.\r\n");
				}
			}
			else
			{
				logMessage("Not a valid transaction file failed to read header.\r\n");
			}
			delete[]temp;
			return ret;
		}

		// Looks up a public key 
		uint32_t getPublicKeyIndex(const char *asciiAddress)
		{
			PublicKeyData a;
			bitcoinAsciiToAddress(asciiAddress, a.address);
			uint32_t ret;
			PublicKey key(a);
			PublicKeySet::iterator found = mPublicKeys.find(key);
			if (found == mPublicKeys.end())
			{
				ret = key.mIndex = uint32_t(mPublicKeys.size()); // note, shouldn't have to worry about overflow for this any time soon....
				mPublicKeys.insert(key);
				mPublicKeyCount++;
			}
			else
			{
				ret = (*found).mIndex;
			}

			assert(ret < mPublicKeyCount);

			return ret;
		}

		// Save all of the public key records we built
		void savePublicKeyRecords(PublicKeyRecord *records)
		{
			logMessage("Saving %s public key records; this is the fully collated set of transactions corresponding to each unique public key address.\r\n", formatNumber(mPublicKeyCount));
			FILE_INTERFACE *fph = fi_fopen(PUBLIC_KEY_RECORDS_FILE_NAME, "wb", nullptr, 0, false);
			if (fph)
			{
				size_t slen = strlen(magicID);
				fi_fwrite(magicID, slen + 1, 1, fph);		// Save the MagicID
				fi_fwrite(&mPublicKeyCount, sizeof(mPublicKeyCount), 1, fph);	// Save the number of public keys

				uint64_t seekLocationsStart = uint64_t(fi_ftell(fph)); // remember the seek location for the seek locations table

				uint64_t *seekLocations = new uint64_t[mPublicKeyCount];	// Allocate memory for the seek locations table

				memset(seekLocations, 0, sizeof(uint64_t)*mPublicKeyCount);	// Zero out the seek locations table
				// Write it out *twice*; once for offsets and the second time will be used for sorting all of the public key records
				fi_fwrite(seekLocations, sizeof(uint64_t)*mPublicKeyCount, 1, fph);
				fi_fwrite(seekLocations, sizeof(uint64_t)*mPublicKeyCount, 1, fph);	// save this out twice; this one reserved for sorting pointers via the MemoryMapped file address space
				// Now, we save each record and, as we do so, we record the seek offset location
				for (uint64_t i = 0; i < mPublicKeyCount; i++)
				{
					seekLocations[i] = uint64_t(fi_ftell(fph)); // remember the offset for this record...
					records[i].save(fph);
				}
				fi_fseek(fph, seekLocationsStart, SEEK_SET);	// Seek back to the start of the offsets table in the file
				fi_fwrite(seekLocations, sizeof(uint64_t)*mPublicKeyCount, 1, fph); // write out the offsets

				delete[]seekLocations;

				fi_fclose(fph);
				logMessage("All records now saved to file '%s'\r\n", PUBLIC_KEY_RECORDS_FILE_NAME);
			}
		}

		// Save all unique public keys
		void savePublicKeyFile(void)
		{
			logMessage("Processed %s transactions.\r\n", formatNumber(int32_t(mTransactions.size())));

			FILE_INTERFACE *fph = fi_fopen(PUBLIC_KEY_FILE_NAME, "wb",nullptr,0,false);
			if (fph)
			{
				size_t slen = strlen(magicID);
				fi_fwrite(magicID, slen + 1, 1, fph);	// Write out the magicID header
				uint32_t count = uint32_t(mPublicKeys.size());
				assert(count == mPublicKeyCount);
				fi_fwrite(&count, sizeof(count), 1, fph);	// Write out the number of public keys
				uint64_t baseLoc = fi_ftell(fph);
				PublicKeyData a;
				for (uint32_t i = 0; i < count; i++)
				{
					fi_fwrite(&a, sizeof(a), 1, fph);
				}
				logMessage("Saving %s public key blocks\r\n", formatNumber(count));
				for (PublicKeySet::iterator i = mPublicKeys.begin(); i != mPublicKeys.end(); ++i)
				{
					const PublicKey &key = (*i);
					uint64_t index = uint64_t(key.mIndex);
					uint64_t offset = (index*sizeof(a)) + baseLoc;
					fi_fseek(fph, offset, SEEK_SET);
					fi_fwrite(key.address, sizeof(key.address), 1, fph);
				}
				fi_fclose(fph);
			}
			else
			{
				logMessage("Failed to open file '%s' for write access\r\n", PUBLIC_KEY_FILE_NAME);
			}
		}

		// load the public keys; does so as a memory mapped file though
		bool loadPublicKeyFile(void)
		{
			bool ret = false;

			if (mAddressFile)
			{
				fi_fclose(mAddressFile);
				mAddressFile = nullptr;
				mAddresses = nullptr;
			}
			mAddresses = nullptr;

			mAddressFile = fi_fopen(PUBLIC_KEY_FILE_NAME, "rb", nullptr, 0, true);
			if (mAddressFile == nullptr)
			{
				logMessage("Failed to open public key file '%s' for read access.\r\n", PUBLIC_KEY_FILE_NAME);
				return false;
			}
			size_t slen = strlen(magicID);
			char *temp = new char[slen + 1];
			size_t r = fi_fread(temp, slen + 1, 1, mAddressFile);
			if (r == 1)
			{
				if (strcmp(temp, magicID) == 0)
				{
					logMessage("Successfully opened the public key file '%s' for read access.\r\n", PUBLIC_KEY_FILE_NAME);
					r = fi_fread(&mPublicKeyCount, sizeof(mPublicKeyCount), 1, mAddressFile);
					if (r == 1)
					{
						logMessage("Reading in %s public keys.\r\n", formatNumber(mPublicKeyCount));
						mAddresses = (PublicKeyData *)fi_getCurrentMemoryLocation(mAddressFile);
					}
					else
					{
						logMessage("Failed to read from public key file.\r\n");
					}
				}
				else
				{
					logMessage("Not a valid header block.\r\n");
				}
			}
			else
			{
				logMessage("Not a valid file failed to read header.\r\n");
			}
			delete[]temp;

			return ret;
		}

		uint32_t computePointerOffset(const void *p1, const void *p2)
		{
			const uint8_t *pt1 = (const uint8_t *)p1;
			const uint8_t *pt2 = (const uint8_t *)p2;
			return (uint32_t)(pt1 - pt2);
		}

		// load the public keys records (as a memory mapped file)
		bool loadPublicKeyRecordsFile(void)
		{
			bool ret = false;

			if (mPublicKeyRecordFile )
			{
				fi_fclose(mPublicKeyRecordFile);
				mPublicKeyRecordFile = nullptr;
				mPublicKeyRecordBaseAddress = nullptr;
				mPublicKeyRecordOffsets = nullptr;
				mPublicKeyRecordSorted = nullptr;
			}

			mPublicKeyRecordFile = fi_fopen(PUBLIC_KEY_RECORDS_FILE_NAME, "rb", nullptr, 0, true);
			if (mPublicKeyRecordFile == nullptr)
			{
				logMessage("Failed to open public key file '%s' for read access.\r\n", PUBLIC_KEY_RECORDS_FILE_NAME);
				return false;
			}
			size_t slen = strlen(magicID);
			char *temp = new char[slen + 1];
			size_t r = fi_fread(temp, slen + 1, 1, mPublicKeyRecordFile);
			if (r == 1)
			{
				if (strcmp(temp, magicID) == 0)
				{
					logMessage("Successfully opened the public key records file '%s' for read access.\r\n", PUBLIC_KEY_RECORDS_FILE_NAME);
					uint32_t publicKeyCount = 0;
					r = fi_fread(&publicKeyCount, sizeof(mPublicKeyCount), 1, mPublicKeyRecordFile);
					if (r == 1)
					{
						mPublicKeyCount = publicKeyCount;
						logMessage("Initializing pointer tables for %s public keys records\r\n", formatNumber(mPublicKeyCount));
						mPublicKeyRecordOffsets = (const uint64_t *)fi_getCurrentMemoryLocation(mPublicKeyRecordFile);
						mPublicKeyRecordSorted = (PublicKeyRecordFile **)(mPublicKeyRecordOffsets + mPublicKeyCount);
						size_t size;
						// This is the base address of the memory mapped file
						mPublicKeyRecordBaseAddress = (uint8_t *)fi_getMemBuffer(mPublicKeyRecordFile, &size);
						// Initialize the public key sorted records array.
						for (uint32_t i = 0; i < mPublicKeyCount; i++)
						{
							uint64_t offset = mPublicKeyRecordOffsets[i];
							uint8_t *ptr = &mPublicKeyRecordBaseAddress[offset];
							PublicKeyRecordFile *pkrf = (PublicKeyRecordFile *)ptr;
							mPublicKeyRecordSorted[i]   = pkrf;
						}
					}
					else
					{
						logMessage("Failed to read from public key records file.\r\n");
					}
				}
				else
				{
					logMessage("Not a valid header block.\r\n");
				}
			}
			else
			{
				logMessage("Not a valid file failed to read header.\r\n");
			}
			delete[]temp;

			return ret;
		}


		virtual void release(void) override final
		{
			delete this;
		}

		bool isValid(void) const
		{
			return mTransactionFile ? true : false;
		}

		// Accessors methods for the public key database
		virtual uint32_t getPublicKeyCount(void)
		{
			return mPublicKeyCount;
		}

		const PublicKeyRecordFile &getPublicKeyRecordFile(uint32_t index)
		{
			uint64_t offset = mPublicKeyRecordOffsets[index];
			const uint8_t *ptr = &mPublicKeyRecordBaseAddress[offset];
			const PublicKeyRecordFile *pkrf = (const PublicKeyRecordFile *)(ptr);
			return *pkrf;
		}

		virtual void printPublicKey(uint32_t index)
		{
			assert(index < mPublicKeyCount);
			const PublicKeyRecordFile &r = getPublicKeyRecordFile(index);
			PublicKeyData &a = mAddresses[index];
			logMessage("==========================================================\r\n");

			logBitcoinAddress(a.address);
			logMessage("\r\n");
			logMessage("%s total transaction on this address.\r\n", formatNumber(int32_t(r.mCount)));

			uint64_t totalSend = r.getTotalSend();
			if (totalSend)
			{
				logMessage("Total Value Sent: %0.2f\r\n", float(totalSend) / ONE_BTC);
			}
			logMessage("Total Value Received: %0.2f\r\n", float(r.getTotalReceive()) / ONE_BTC);
			logMessage("Balance: %0.2f\r\n", float(r.getBalance()) / ONE_BTC);
			uint32_t lastSendTime = r.getLastSendTime();
			if (lastSendTime)
			{
				logMessage("LastSend: %s\r\n", getTimeString(lastSendTime));
			}
			uint32_t lastReceiveTime = r.getLastReceiveTime();
			if (lastReceiveTime)
			{
				logMessage("LastReceive: %s\r\n", getTimeString(lastReceiveTime));
			}

			uint32_t count = uint32_t(r.mCount);
			for (uint32_t i = 0; i<count; i++)
			{
				const PublicKeyTransaction &t = r.mTransactions[i];
				const char *prefix = "";
				if (t.mSpend)
				{
					prefix = "Send";
				}
				else
				{
					if (t.mCoinbase)
					{
						prefix = "Coinbase";
					}
					else
					{
						prefix = t.mChange ? "Change" : "Receive";
					}
				}
				logMessage("%10s : %10s : %0.2f \r\n", prefix, getTimeString(t.mTimeStamp), float(t.mValue) / ONE_BTC );
			}


			logMessage("==========================================================\r\n");
			logMessage("\r\n");
		}

	private:
		bool						mAnalyze;
		TransactionHashSet			mTransactions;		// The list of all transaction hashes
		FILE_INTERFACE				*mTransactionFile;	// The data file which holds all transactions; too large to fit into memory
		PublicKeySet				mPublicKeys;		// the list of public keys in an STL set; built during blockchain processing phase

		uint32_t					mPublicKeyCount;	// Total number of unique public keys in the bockchain
		FILE_INTERFACE				*mAddressFile;		// The memory mapped file for the public-keys
		PublicKeyData				*mAddresses;		// The array of public keys; accessed via a memory mapped file...

		FILE_INTERFACE				*mPublicKeyRecordFile;
		uint8_t						*mPublicKeyRecordBaseAddress;			// The base address of the memory mapped file
		const uint64_t				*mPublicKeyRecordOffsets;		// Offsets 
		PublicKeyRecordFile			**mPublicKeyRecordSorted;		// Public key records sorted
	};

}

PublicKeyDatabase * PublicKeyDatabase::create(bool analyze)
{
	PUBLIC_KEY_DATABASE::PublicKeyDatabaseImpl *p = new PUBLIC_KEY_DATABASE::PublicKeyDatabaseImpl(analyze);
	if (!p->isValid())
	{
		p->release();
		p = nullptr;
	}
	return static_cast<PublicKeyDatabase *>(p);
}
