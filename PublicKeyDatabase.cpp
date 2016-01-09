#include "PublicKeyDatabase.h"
#include "BitcoinAddress.h"
#include "FileInterface.h"
#include "logging.h"
#include "HeapSort.h"

#include "CRC32.h"

#include <stdio.h>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <assert.h>
#include <time.h>

#define ONE_BTC 100000000
#define ONE_MBTC (ONE_BTC/1000)
#define SECONDS_PER_DAY (60*60*24)

#ifdef _MSC_VER
#pragma warning(disable:4100 4996 4189)
#endif

namespace PUBLIC_KEY_DATABASE
{

#define MAXIMUM_DAYS (365*10)	// Leave room for 10 years of days

	class DailyStatistics
	{
	public:

		DailyStatistics(void)
		{
			memset(this, sizeof(DailyStatistics), 0);
		}

		uint32_t getMeanInputCount(void) const
		{
			return mTransactionCount ? mInputCount / mTransactionCount : 0;
		}

		uint32_t getMeanOutputCount(void) const
		{
			return mTransactionCount ? mOutputCount / mTransactionCount : 0;
		}

		uint32_t getMeanTransactionSize(void) const
		{
			return mTransactionCount ? mTransactionSize / mTransactionCount : 0;
		}

		uint32_t	mTimeStamp;								// The time stamp for this day
		uint32_t	mTransactionCount;						// How many transactions happened on this day
		uint32_t	mInputCount;							// Total number of inputs in all transactions
		uint32_t	mOutputCount;							// Total number of outputs in all transactions
		uint32_t	mMaxInputCount;							// Largest number of transaction inputs on this day
		uint32_t	mMaxOutputCount;						// Largest number of transaction outputs on this day
		uint32_t	mTransactionSize;						// Size of all transactions on this day
		uint32_t	mMaxTransactionSize;					// Maximum transaction size on this day
		uint32_t	mKeyTypeCounts[BlockChain::KT_LAST];	// Counts of various types of keys
		double		mTotalInputValue;						// Total value of all inputs for this day
		double		mTotalOutputValue;						// Total value of all outputs for this day
		uint32_t	mTotalInputScriptLength;				// Total size of all input scripts for this day
		uint32_t	mTotalOutputScriptLength;				// Total size of all output scripts for this day
		uint32_t	mMaxInputScriptLength;					// Maximum input script length on this day
		uint32_t	mMaxOutputScriptLength;					// Maximum output script length on this day
		uint32_t	mCurrentBlock;							// The current blockf or this day
		uint32_t	mTransactionBlockCount;					// How many transactions are in the current block
		uint32_t	mBlockCount;							// Number of blocks on this day
		uint32_t	mMaxTransactionBlockCount;			// Maximum number of transactions in a block
	};


	const uint32_t BITCOIN_START_DATE = 1231001362;

	uint32_t getAgeInDays(uint32_t timestamp)
	{
		uint32_t diff = timestamp - BITCOIN_START_DATE;
		uint32_t days = diff / SECONDS_PER_DAY;
		return days;
	}

	uint32_t getAgeInDaysCurrent(uint32_t timestamp)
	{
		time_t t;
		time(&t);
		uint32_t diff = uint32_t(t) - timestamp;
		uint32_t days = diff / SECONDS_PER_DAY;
		return days;
	}


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
		uint64_t	mBalance;				// 8  : 
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
			uint32_t padding = 0;
			uint64_t padding64 = 0;
			fi_fwrite(&padding, sizeof(padding), 1, fph);

			fi_fwrite(&padding64, sizeof(padding64), 1, fph);	// Will be the balance field in PublicKeyRecordFile
			fi_fwrite(&padding, sizeof(padding), 1, fph);		// Will be the LastSendTime field in the PublicKeyRecordFile
			fi_fwrite(&padding, sizeof(padding), 1, fph);		// Will be the LastReceiveTime field in the PublicKeyRecordFile
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

		uint64_t getBalance(uint32_t endTime=0xFFFFFFFF) const
		{
			uint64_t ret = 0;
			for (uint32_t i = 0; i < mCount; i++)
			{
				const PublicKeyTransaction &t = mTransactions[i];
				if (t.mTimeStamp > endTime)
				{
					break;
				}
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

		uint64_t getTotalSend(uint32_t endTime=0xFFFFFFFF) const
		{
			uint64_t ret = 0;
			for (uint32_t i = 0; i < mCount; i++)
			{
				const PublicKeyTransaction &t = mTransactions[i];
				if (t.mTimeStamp > endTime)
				{
					break;
				}
				if (t.mSpend)
				{
					ret += t.mValue;
				}
			}
			return ret;
		}

		uint64_t getTotalReceive(uint32_t endTime=0xFFFFFFFF) const
		{
			uint64_t ret = 0;
			for (uint32_t i = 0; i < mCount; i++)
			{
				const PublicKeyTransaction &t = mTransactions[i];
				if (t.mTimeStamp > endTime)
				{
					break;
				}
				if (!t.mSpend)
				{
					ret += t.mValue;
				}
			}
			return ret;
		}

		uint32_t getLastSendTime(uint32_t endTime=0xFFFFFFFF) const
		{
			uint32_t ret = 0;

			uint32_t count = mCount;
			if (count)
			{
				uint32_t index = count - 1;
				for (uint32_t i = 0; i < count; i++, index--)
				{
					const PublicKeyTransaction &t = mTransactions[index];
					if (t.mTimeStamp > endTime)
					{
						continue;
					}
					if (t.mSpend)
					{
						ret = t.mTimeStamp;
						break;
					}
				}
			}
			return ret;
		}


		uint32_t getLastReceiveTime(uint32_t endTime=0xFFFFFFFF) const
		{
			uint32_t ret = 0;

			uint32_t count = mCount;
			if (count)
			{
				uint32_t index = count - 1;
				for (uint32_t i = 0; i < count; i++, index--)
				{
					const PublicKeyTransaction &t = mTransactions[index];
					if (t.mTimeStamp > endTime)
					{
						continue;
					}
					if (!t.mSpend)
					{
						ret = t.mTimeStamp;
						break;
					}
				}
			}
			return ret;
		}

		uint32_t getAge(void)
		{
			uint32_t lastTime;
			if ( mLastSendTime)
			{
				lastTime = mLastSendTime;
			}
			else
			{
				lastTime = mTransactions[0].mTimeStamp;
			}
			uint32_t daysOld = getAgeInDaysCurrent(lastTime);
			return daysOld;
		}

		void computeBalance(uint32_t endTime=0xFFFFFFFF) // compute the balance, up to this time stamp
		{
			mBalance			= getBalance(endTime);
			mLastSendTime		= getLastSendTime(endTime);
			mLastReceiveTime	= getLastReceiveTime(endTime);
			mDaysOld			= getAge();
		}

		BlockChain::KeyType			mKeyType;			// What type of bitcoin key is this?  Standard, MultiSig, Pay2Hash, Stealth?
		uint32_t					mIndex;				// Array index for public key
		uint32_t					mCount;				// Number of transactions associated with this public key
		uint32_t					mDaysOld;			// Must be here because the PublicKeyTransaction is going to be 16 byte aligned!

		uint64_t					mBalance;			// 8 bytes Balance.
		uint32_t					mLastSendTime;		// compute the time of last sent transaction
		uint32_t					mLastReceiveTime;	// compute the time of the last receive transaction

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
			mScriptLength = bo.challengeScriptLength;
		}

		TransactionOutput(FILE_INTERFACE *fph)
		{
			fi_fread(&mValue, sizeof(mValue), 1, fph);
			fi_fread(&mIndex, sizeof(mIndex), 1, fph);
			fi_fread(&mKeyType, sizeof(mKeyType), 1, fph);
			fi_fread(&mScriptLength, sizeof(mScriptLength), 1, fph);
		}


		void save(FILE_INTERFACE *fph)
		{
			fi_fwrite(&mValue, sizeof(mValue), 1, fph);
			fi_fwrite(&mIndex, sizeof(mIndex), 1, fph);
			fi_fwrite(&mKeyType, sizeof(mKeyType), 1, fph);
			fi_fwrite(&mScriptLength, sizeof(mScriptLength), 1, fph );
		}

		void echo(void)
		{

		}

		uint64_t					mValue;		// The value of the output
		uint32_t					mIndex;		// The array index for this public key (stored in a separate table)
		BlockChain::KeyType			mKeyType;	// type of key
		uint32_t					mScriptLength;
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
			mResponseScriptLength = bi.responseScriptLength;
		}

		TransactionInput(FILE_INTERFACE *fph)
		{
			fi_fread(&mTransactionFileOffset, sizeof(mTransactionFileOffset), 1, fph);
			fi_fread(&mTransactionIndex, sizeof(mTransactionIndex), 1, fph);
			fi_fread(&mInputValue, sizeof(mInputValue), 1, fph);
			fi_fread(&mResponseScriptLength, sizeof(mResponseScriptLength), 1, fph);
		}

		void save(FILE_INTERFACE *fph)
		{
			fi_fwrite(&mTransactionFileOffset, sizeof(mTransactionFileOffset), 1, fph);
			fi_fwrite(&mTransactionIndex, sizeof(mTransactionIndex), 1, fph);
			fi_fwrite(&mInputValue, sizeof(mInputValue), 1, fph);
			fi_fwrite(&mResponseScriptLength, sizeof(mResponseScriptLength), 1, fph);
		}

		void echo(void)
		{

		}

		uint64_t	mTransactionFileOffset;			// Which transaction this input refers to (0 means coinbase)
		uint32_t	mTransactionIndex;				// Which output forms this input
		uint32_t	mResponseScriptLength;			// The length of the response script
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
			mTransactionSize = t.transactionLength;
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
				fi_fread(&mTransactionSize, sizeof(mTransactionSize), 1, fph);
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
			fi_fwrite(&mTransactionSize, sizeof(mTransactionSize), 1, fph);
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
		uint32_t					mTransactionSize;					// The size of the transaction (in bytes)
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

// Sorting classes
	class SortByBalance : public HeapSortPointers
	{
	public:
		// -1 less, 0 equal, +1 greater.
		virtual int32_t compare(void *p1, void *p2) override final
		{
			PublicKeyRecordFile *pkr1 = (PublicKeyRecordFile *)p1;
			PublicKeyRecordFile *pkr2 = (PublicKeyRecordFile *)p2;
			if (pkr1->mBalance < pkr2->mBalance)
			{
				return 1;
			}
			if (pkr1->mBalance > pkr2->mBalance)
			{
				return -1;
			}
			return 0;
		}
	};



	class PublicKeyDatabaseImpl : public PublicKeyDatabase
	{
	public:
		PublicKeyDatabaseImpl(bool analyze) : mPublicKeyCount(0)
			, mTransactionFile(nullptr)
			, mPublicKeyFile(nullptr)
			, mAnalyze(analyze)
			, mAddresses(nullptr)
			, mAddressFile(nullptr)
			, mPublicKeyRecordFile(nullptr)
			, mPublicKeyRecordBaseAddress(nullptr)
			, mPublicKeyRecordOffsets(nullptr)
			, mPublicKeyRecordSorted(nullptr)
			, mTransactionFileCountSeekLocation(0)
			, mPublicKeyFileCountSeekLocation(0)
			, mTransactionCount(0)
			, mDailyStatistics(nullptr)
			, mFirstTransactionOffset(0)
		{
			if (analyze)
			{
				openTransactionsFile();
				loadPublicKeyFile();
				loadPublicKeyRecordsFile();
			}
			else
			{
				uint32_t key = 'y';
				FILE_INTERFACE *fph = fi_fopen(TRANSACTION_FILE_NAME, "rb", 0, 0, false);
				if (fph)
				{
					fi_fclose(fph);
					logMessage("A pre-processed transactions database already exists!\r\n");
					logMessage("Are you sure you want to delete it and start over?\r\n");
					logMessage("Press 'y' to continue, any other key to cancel.\r\n");
					key = getKey();
				}
				if (key == 'y')
				{
					fi_deleteFile(PUBLIC_KEY_RECORDS_FILE_NAME);
					mTransactionFile = fi_fopen(TRANSACTION_FILE_NAME, "wb", nullptr, 0, false);
					if (mTransactionFile)
					{
						size_t slen = strlen(magicID);
						fi_fwrite(magicID, slen + 1, 1, mTransactionFile);
						mTransactionFileCountSeekLocation = uint32_t(fi_ftell(mTransactionFile));
						fi_fwrite(&mTransactionCount, sizeof(mTransactionCount), 1, mTransactionFile); // save the number of transactions
						fi_fflush(mTransactionFile);
						mPublicKeyFile = fi_fopen(PUBLIC_KEY_FILE_NAME, "wb", nullptr, 0, false);
						if (mPublicKeyFile)
						{
							size_t slen = strlen(magicID);
							fi_fwrite(magicID, slen + 1, 1, mPublicKeyFile);
							mPublicKeyFileCountSeekLocation = uint32_t(fi_ftell(mPublicKeyFile));
							fi_fwrite(&mPublicKeyCount, sizeof(mPublicKeyCount), 1, mPublicKeyFile); // save the number of transactions
							fi_fflush(mPublicKeyFile);
						}
						else
						{
							logMessage("Failed to open file '%s' for write access.\r\n", PUBLIC_KEY_FILE_NAME);
						}
					}
					else
					{
						logMessage("Failed to open file '%s' for write access.\r\n", TRANSACTION_FILE_NAME);
					}
				}
			}
		}

		virtual ~PublicKeyDatabaseImpl(void)
		{
			logMessage("~PublicKeyDatabaseImpl destructor\r\n");
			delete[]mDailyStatistics;
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

				TransactionHashSet::iterator found = mTransactions.find(th);
				if (found != mTransactions.end() )
				{
					logMessage("Encountered the same transaction hash twice; this appears to be a bug and must be fixed! Ignoring second occurence for now.\r\n");
					logMessage("DuplicateHash:");
					printReverseHash((const uint8_t *)&th.mWord0);
					logMessage("\r\n");
				}
				else
				{
					mTransactionCount++;	// increment the transaction count
					mTransactions.insert(th);	// Add it to the transaction hash table; so we can convert from a transaction hash to a file offset quickly and efficiently
				}
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
				closePublicKeyFile();
				mTransactionFile = nullptr;
				logMessage("Clearing transactions container\r\n");
				mTransactions.clear();		// We no longer need this hash-set of transaction hashes since we have rebased the data based the data based on transaction offset into the datafile

				logMessage("Clearing PublicKeys container\r\n");
				mPublicKeys.clear();		// We no longer needs this hash set, so free up the memory
				mAnalyze = true;
				logMessage("Opening the transactions file\r\n");
				openTransactionsFile();
				logMessage("Loading the PublicKey address file\r\n");
				loadPublicKeyFile();
			}
			logMessage("Creating PublicKey records data  set.\r\n");
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
					if (ti.mTransactionIndex < inputTransaction.mOutputs.size())
					{
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
						logMessage("Invalid transaction index of %d; maximum outputs in this transaction are %d\r\n", ti.mTransactionIndex, inputTransaction.mOutputs.size());
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
							if (ti.mTransactionIndex < inputTransaction.mOutputs.size())
							{
								TransactionOutput &pto = inputTransaction.mOutputs[ti.mTransactionIndex];
								if (pto.mIndex == to.mIndex)
								{
									pt.mChange = true;
									break;
								}
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

		bool seekFirstTransaction(void)
		{
			if (!mTransactionFile)
			{
				return false;
			}
			if (!mFirstTransactionOffset)
			{
				return false;
			}
			fi_fseek(mTransactionFile, mFirstTransactionOffset, SEEK_SET);
			uint64_t t = fi_ftell(mTransactionFile);
			return t == mFirstTransactionOffset;
		}

		// Opens a previously saved transactions file (as a memory mapped file so we don't use up system memory)
		bool openTransactionsFile(void)
		{
			if (mTransactionFile)
			{
				return false;
			}
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
					fi_fread(&mTransactionCount, sizeof(mTransactionCount), 1, mTransactionFile);
					assert(mTransactionCount); // if this is zero then the transaction file didn't close cleanly, we could dervive this value if necessary.
					mFirstTransactionOffset = fi_ftell(mTransactionFile);
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
				fi_fwrite(a.address, sizeof(a.address), 1, mPublicKeyFile);
				fi_fflush(mPublicKeyFile);
				mPublicKeyCount++;
			}
			else
			{
				ret = (*found).mIndex;
			}

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

		// Close the unique public keys file
		void closePublicKeyFile(void)
		{
			assert(mTransactionCount == uint32_t(mTransactions.size()));
			assert(mPublicKeyCount == uint32_t(mPublicKeys.size()));

			// Write out the total number of transactions and then close the transactions file
			if (mTransactionFile)
			{
				logMessage("Closing the transaction file which contains %s transactions.\r\n", formatNumber(mTransactionCount));
				fi_fseek(mTransactionFile, mTransactionFileCountSeekLocation, SEEK_SET);
				fi_fwrite(&mTransactionCount, sizeof(mTransactionCount), 1, mTransactionFile);
				fi_fclose(mTransactionFile);
				mTransactionFile = nullptr;
			}
			else
			{
				assert(0);
			}
			logMessage("Processed %s transactions with %s unique public keys.\r\n", formatNumber(int32_t(mTransactionCount)), formatNumber(int32_t(mPublicKeyCount)));
			if (mPublicKeyFile)
			{
				logMessage("Closing the PublicKeys file\r\n");
				fi_fseek(mPublicKeyFile, mPublicKeyFileCountSeekLocation, SEEK_SET);
				fi_fwrite(&mPublicKeyCount, sizeof(mPublicKeyCount), 1, mPublicKeyFile);
				fi_fclose(mPublicKeyFile);
				mPublicKeyFile = nullptr;
			}
			else
			{
				assert(0);
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
					r = fi_fread(&publicKeyCount, sizeof(publicKeyCount), 1, mPublicKeyRecordFile);
					if (r == 1)
					{
						assert(publicKeyCount); // if the public key count is zero; this probably indicates that the file did not close cleanly on creation. We could derive the count if necessary...
						assert(publicKeyCount == mPublicKeyCount);
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

		PublicKeyRecordFile &getPublicKeyRecordFile(uint32_t index)
		{
			uint64_t offset = mPublicKeyRecordOffsets[index];
			uint8_t *ptr = &mPublicKeyRecordBaseAddress[offset];
			PublicKeyRecordFile *pkrf = (PublicKeyRecordFile *)(ptr);
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

		void initByTime(uint32_t timeStamp)
		{
			logMessage("Computing balances up to this date: %s\r\n", getTimeString(timeStamp));
			for (uint32_t i = 0; i < mPublicKeyCount; i++)
			{
				PublicKeyRecordFile &pkrf = getPublicKeyRecordFile(i);
				pkrf.computeBalance(timeStamp);
				mPublicKeyRecordSorted[i] = &pkrf;
			}
		}

		// Generates the top balance report; writtent to 'TopBalances.txt'
		virtual void reportTopBalances(const char *reportFileName,uint32_t maxReport,uint32_t timeStamp)
		{
			initByTime(timeStamp);
			logMessage("Finished computing balances for %s public keys.\r\n", formatNumber(mPublicKeyCount));
			logMessage("Sorting by balance.\r\n");
			SortByBalance sbb;
			sbb.heapSort((void **)(mPublicKeyRecordSorted), mPublicKeyCount);
			FILE *fph = fopen(reportFileName, "wb");
			if (fph)
			{
				fprintf(fph, "PublicKey,Balance,Age\r\n");
				if (maxReport > mPublicKeyCount)
				{
					maxReport = mPublicKeyCount;
				}

				time_t curTime;
				time(&curTime);

				for (uint32_t i = 0; i < maxReport; i++)
				{
					PublicKeyRecordFile &pkrf = *mPublicKeyRecordSorted[i];
					PublicKeyData &a = mAddresses[pkrf.mIndex];
					fprintf(fph, "%s,%0.2f,%d\r\n", getBitcoinAddressAscii(a.address), (float)pkrf.mBalance / ONE_BTC, pkrf.mDaysOld);
				}
				fclose(fph);
			}
			else
			{
				logMessage("Failed to open report file '%s' for write access\r\n");
			}
		}


		time_t getMonthDayYear(uint32_t month, uint32_t day, uint32_t year)
		{
			time_t rawtime;
			time(&rawtime);
			struct tm *timeinfo = localtime(&rawtime);
			timeinfo->tm_year = year - 1900;
			timeinfo->tm_mon = month - 1;
			timeinfo->tm_mday = day;
			return _mkgmtime(timeinfo);
		}

		// Will generate a spreadsheet of bitcoin balances sorted by age of last access
		virtual void reportByAge(const char *reportName)
		{

		}

		// compute the transaction statistics on a daily basis for the entire history of the blockchain
		virtual void reportDailyTransactions(const char *reportFileName)
		{
			delete[]mDailyStatistics;
			mDailyStatistics = new DailyStatistics[MAXIMUM_DAYS];
			memset(mDailyStatistics,0,sizeof(DailyStatistics)*MAXIMUM_DAYS);
			time_t curTime;
			time(&curTime);		// get the current 'real' time; if we go past it, we stop..

			seekFirstTransaction();
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
				computeTransactionStatistics(t,toffset);
			}

			FILE_INTERFACE *fph = fi_fopen(reportFileName, "wb", nullptr, 0, false);
			if (fph)
			{
				logMessage("Generating daily transactions report to file '%s'\r\n", reportFileName);
				fi_fprintf(fph,"Date,TransactiontCount\r\n");
				for (uint32_t i = 0; i < MAXIMUM_DAYS; i++)
				{
					if (noMoreDays(i))
					{
						break;
					}
					DailyStatistics &d = mDailyStatistics[i];
					if (d.mTimeStamp)
					{
						fi_fprintf(fph, "%s,%d\r\n", getDateString(d.mTimeStamp), d.mTransactionCount);
					}
				}
				fi_fclose(fph);
			}
			else
			{
				logMessage("Failed to open file '%s' for write access.\r\n", reportFileName);
			}

		}

		bool noMoreDays(uint32_t index)
		{
			// look for no new data for two weeks in which case, this is EOF
			bool ret = true;

			for (uint32_t i = 0; i < 7; i++)
			{
				uint32_t day = index + i;
				if (day < MAXIMUM_DAYS)
				{
					DailyStatistics &d = mDailyStatistics[index + i];
					if (d.mTimeStamp)
					{
						ret = false;
						break;
					}
				}
				else
				{
					break;
				}
			}

			return ret;
		}

		void computeTransactionStatistics(const Transaction &t, uint64_t toffset)
		{
			uint32_t days = getAgeInDays(t.mTransactionTime);
			assert(days < MAXIMUM_DAYS);
			DailyStatistics &d = mDailyStatistics[days];
			d.mTransactionCount++;
			d.mTransactionSize += t.mTransactionSize;
			if (d.mTimeStamp == 0)
			{
				d.mTimeStamp = t.mTransactionTime;
			}
		}



	private:
		bool						mAnalyze;
		uint64_t					mFirstTransactionOffset;	// the first transaction offset
		TransactionHashSet			mTransactions;		// The list of all transaction hashes
		FILE_INTERFACE				*mPublicKeyFile;	// The data file which holds all unique public keys
		FILE_INTERFACE				*mTransactionFile;	// The data file which holds all transactions; too large to fit into memory
		PublicKeySet				mPublicKeys;		// the list of public keys in an STL set; built during blockchain processing phase
		uint32_t					mTransactionFileCountSeekLocation;
		uint32_t					mPublicKeyFileCountSeekLocation;
		uint32_t					mTransactionCount;

		uint32_t					mPublicKeyCount;	// Total number of unique public keys in the bockchain
		FILE_INTERFACE				*mAddressFile;		// The memory mapped file for the public-keys
		PublicKeyData				*mAddresses;		// The array of public keys; accessed via a memory mapped file...

		FILE_INTERFACE				*mPublicKeyRecordFile;
		uint8_t						*mPublicKeyRecordBaseAddress;			// The base address of the memory mapped file
		const uint64_t				*mPublicKeyRecordOffsets;		// Offsets 
		PublicKeyRecordFile			**mPublicKeyRecordSorted;		// Public key records sorted

		DailyStatistics				*mDailyStatistics; // room to compute daily statistics
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
