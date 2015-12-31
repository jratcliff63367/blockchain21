#include "PublicKeyDatabase.h"
#include "BitcoinAddress.h"
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
		uint64_t	mTransactionOffset;		// The file offset location to the full transaction details
		uint64_t	mValue;					// How much value is in this spend/receive transaction
		uint32_t	mTimeStamp;				// Time stamp for this transaction
		bool		mSpend : 1;				// is it a spend transaction?
		bool		mCoinbase : 1;			// is it a coinbase transaction
		bool		mChange : 1;			// Whether or not this receive was change (came from ourselves)
	};

	typedef std::vector< PublicKeyTransaction > PublicKeyTransactionVector;

	// This class represents the collection of all transactions associated with a particular public key
	class PublicKeyRecord
	{
	public:

		uint64_t getBalance(void) const
		{
			uint64_t ret = 0;
			for (auto i = mTransactions.begin(); i != mTransactions.end(); ++i)
			{
				const PublicKeyTransaction &t = (*i);
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
			for (auto i = mTransactions.begin(); i != mTransactions.end(); ++i)
			{
				const PublicKeyTransaction &t = (*i);
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
			for (auto i = mTransactions.begin(); i != mTransactions.end(); ++i)
			{
				const PublicKeyTransaction &t = (*i);
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

			uint32_t count = uint32_t(mTransactions.size());
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

			uint32_t count = uint32_t(mTransactions.size());
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

		PublicKeyTransactionVector	mTransactions;		// all transactions in chronological order relative to this public key
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

		TransactionOutput(FILE *fph)
		{
			fread(&mValue, sizeof(mValue), 1, fph);
			fread(&mIndex, sizeof(mIndex), 1, fph);
			fread(&mKeyType, sizeof(mKeyType), 1, fph);
		}


		void save(FILE *fph)
		{
			fwrite(&mValue, sizeof(mValue), 1, fph);
			fwrite(&mIndex, sizeof(mIndex), 1, fph);
			fwrite(&mKeyType, sizeof(mKeyType), 1, fph);
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

		TransactionInput(FILE *fph)
		{
			fread(&mTransactionFileOffset, sizeof(mTransactionFileOffset), 1, fph);
			fread(&mTransactionIndex, sizeof(mTransactionIndex), 1, fph);
			fread(&mInputValue, sizeof(mInputValue), 1, fph);
		}

		void save(FILE *fph)
		{
			fwrite(&mTransactionFileOffset, sizeof(mTransactionFileOffset), 1, fph);
			fwrite(&mTransactionIndex, sizeof(mTransactionIndex), 1, fph);
			fwrite(&mInputValue, sizeof(mInputValue), 1, fph);
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

		bool read(FILE *fph)
		{
			bool ret = true;

			mInputs.clear();
			mOutputs.clear();
			size_t r = fread(mTransactionHash, sizeof(mTransactionHash), 1, fph);		// Write out the transaction hash
			if (r != 1)
			{
				ret = false;
			}
			else
			{
				fread(&mBlockNumber, sizeof(mBlockNumber), 1, fph);		// Write out the transaction hash
				fread(&mTransactionVersionNumber, sizeof(mTransactionVersionNumber), 1, fph);	// Write out the transaction version number
				fread(&mTransactionTime, sizeof(mTransactionTime), 1, fph);		// Write out the block-time of this transaction.
				fread(&mLockTime, sizeof(mLockTime), 1, fph);						// Write out the lock-time of this transaction.
				uint32_t count;
				fread(&count, sizeof(count), 1, fph);
				mInputs.reserve(count);
				for (uint32_t i = 0; i < count; i++)
				{
					TransactionInput ti(fph);
					mInputs.push_back(ti);
				}
				fread(&count, sizeof(count), 1, fph);
				mOutputs.reserve(count);
				for (uint32_t i = 0; i < count; i++)
				{
					TransactionOutput to(fph);
					mOutputs.push_back(to);
				}
			}


			return ret;
		}

		void save(FILE *fph)
		{
			fwrite(mTransactionHash, sizeof(mTransactionHash), 1, fph);		// Write out the transaction hash
			fwrite(&mBlockNumber, sizeof(mBlockNumber), 1, fph);		// Write out the transaction hash
			fwrite(&mTransactionVersionNumber, sizeof(mTransactionVersionNumber), 1, fph);	// Write out the transaction version number
			fwrite(&mTransactionTime, sizeof(mTransactionTime), 1, fph);		// Write out the block-time of this transaction.
			fwrite(&mLockTime, sizeof(mLockTime), 1, fph);						// Write out the lock-time of this transaction.
			uint32_t count = uint32_t(mInputs.size());							// Write out the number of transaction inputs
			fwrite(&count, sizeof(count), 1, fph);
			for (uint32_t i = 0; i < count; i++)
			{
				mInputs[i].save(fph);	// Save each input
			}
			count = uint32_t(mOutputs.size());			// Write out the number of transaction outputs
			fwrite(&count, sizeof(count), 1, fph);		
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

#define TRANSACTION_FILE_NAME "TransactionFile.bin"
#define PUBLIC_KEY_FILE_NAME "PublicKeys.bin"

	typedef std::unordered_set< PublicKey >			PublicKeySet;			// The unordered set of all public keys
	typedef std::unordered_set< TransactionHash >	TransactionHashSet;		// The unordered set of all transactions; only contains the file seek offset

	const char *magicID = "PublicKeyDatabase";

	class PublicKeyDatabaseImpl : public PublicKeyDatabase
	{
	public:
		PublicKeyDatabaseImpl(bool analyze) : mPublicKeyCount(0), mTransactionFile(nullptr), mAnalyze(analyze), mAddresses(nullptr), mRecords(nullptr)
		{
			if (analyze)
			{
				openTransactionsFile();
				loadPublicKeyFile();
			}
			else
			{
				mTransactionFile = fopen(TRANSACTION_FILE_NAME, "wb");
				if (mTransactionFile)
				{
					size_t slen = strlen(magicID);
					fwrite(magicID, slen + 1, 1, mTransactionFile);
					fflush(mTransactionFile);
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
				fclose(mTransactionFile);
				if (!mAnalyze)
				{
					savePublicKeyFile();
				}
			}
			delete[]mAddresses;
			delete[]mRecords;
		}

		virtual void addBlock(const BlockChain::Block *b) override final
		{
			if (!mTransactionFile || mAnalyze )
			{
				return;
			}
			for (uint32_t i = 0; i < b->transactionCount; i++)
			{
				uint64_t fileOffset = uint64_t(ftell(mTransactionFile)); // the file offset for this transaction data
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
			fflush(mTransactionFile);
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
				mTransactionFile = nullptr;
				mTransactions.clear();		// We no longer need this hash-set of transaction hashes since we have rebased the data based the data based on transaction offset into the datafile
				mPublicKeys.clear();		// We no longer needs this hash set, so free up the memory
				mAnalyze = true;
				openTransactionsFile();
				loadPublicKeyFile();
			}
			logMessage("Building PublicKey records.\r\n");
			uint32_t transactionCount = 0;
			uint64_t transactionOffset = uint64_t(ftell(mTransactionFile));
			Transaction t;
			while (readTransaction(t, transactionOffset))
			{
				transactionCount++;
				if ((transactionCount % 1000) == 0)
				{
					logMessage("Processing transaction %s\r\n", formatNumber(transactionCount));
				}
				uint64_t toffset = transactionOffset; // the base transaction offset
				transactionOffset = uint64_t(ftell(mTransactionFile));
				processTransaction(t,toffset);
				// do stuff here...
			}
		}

		void processTransaction(const Transaction &t,uint64_t transactionOffset)
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
					PublicKeyRecord &record = mRecords[to.mIndex]; // ok...let's get the record
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

				PublicKeyRecord &record = mRecords[to.mIndex]; // ok...let's get the record

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
		}

		bool readTransaction(Transaction &t, uint64_t transactionOffset)
		{
			bool ret = false;

			{
				_fseeki64(mTransactionFile, size_t(transactionOffset), SEEK_SET);
				uint64_t actual = uint64_t(ftell(mTransactionFile));
				if (actual == transactionOffset)
				{
					ret = t.read(mTransactionFile); // read this transaction 
				}
			}

			return ret;
		}

		bool openTransactionsFile(void)
		{
			if (mTransactionFile) return false;
			mTransactionFile = fopen(TRANSACTION_FILE_NAME, "rb");
			if (mTransactionFile == nullptr)
			{
				logMessage("Failed to open transaction file '%s' for read access.\r\n", TRANSACTION_FILE_NAME);
				return false;
			}
			size_t slen = strlen(magicID);
			char *temp = new char[slen + 1];
			size_t r = fread(temp, slen + 1, 1, mTransactionFile);
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

		uint32_t getPublicKeyIndex(const char *asciiAddress)
		{
			PublicKeyData a;
			bitcoinAsciiToAddress(asciiAddress, a.address);
			uint32_t ret;
			mPublicKeyCount++;
			PublicKey key(a);
			PublicKeySet::iterator found = mPublicKeys.find(key);
			if (found == mPublicKeys.end())
			{
				ret = key.mIndex = uint32_t(mPublicKeys.size()); // note, shouldn't have to worry about overflow for this any time soon....
				mPublicKeys.insert(key);
			}
			else
			{
				ret = (*found).mIndex;
			}

			return ret;
		}

		void savePublicKeyFile(void)
		{
			logMessage("Processed %s transactions.\r\n", formatNumber(int32_t(mTransactions.size())));
			FILE *fph = fopen(PUBLIC_KEY_FILE_NAME, "wb");
			if (fph)
			{
				size_t slen = strlen(magicID);
				fwrite(magicID, slen + 1, 1, fph);
				uint32_t count = uint32_t(mPublicKeys.size());
				logMessage("Saving %s unique public keys from %s keys encountered; saving a total of %s\r\n", formatNumber(count), formatNumber(mPublicKeyCount), formatNumber(mPublicKeyCount - count));
				fwrite(&count, sizeof(count), 1, fph);

				uint64_t baseLoc = ftell(fph);
				PublicKeyData a;
				for (uint32_t i = 0; i < count; i++)
				{
					fwrite(&a, sizeof(a), 1, fph);
				}
				logMessage("Saving %s public key blocks\r\n", formatNumber(count));
				for (PublicKeySet::iterator i = mPublicKeys.begin(); i != mPublicKeys.end(); ++i)
				{
					const PublicKey &key = (*i);
					uint64_t index = uint64_t(key.mIndex);
					uint64_t offset = (index*sizeof(a)) + baseLoc;
					_fseeki64(fph, offset, SEEK_SET);
					fwrite(key.address, sizeof(key.address), 1, fph);
				}
				fclose(fph);
			}
			else
			{
				logMessage("Failed to open file '%s' for write access\r\n", PUBLIC_KEY_FILE_NAME);
			}
		}

		bool loadPublicKeyFile(void)
		{
			bool ret = false;

			delete[]mAddresses;
			mAddresses = nullptr;
			delete[]mRecords;
			mRecords = nullptr;

			FILE *fph = fopen(PUBLIC_KEY_FILE_NAME, "rb");
			if (fph == nullptr)
			{
				logMessage("Failed to open public key file '%s' for read access.\r\n", PUBLIC_KEY_FILE_NAME);
				return false;
			}
			size_t slen = strlen(magicID);
			char *temp = new char[slen + 1];
			size_t r = fread(temp, slen + 1, 1, fph);
			if (r == 1)
			{
				if (strcmp(temp, magicID) == 0)
				{
					logMessage("Successfully opened the public key file '%s' for read access.\r\n", PUBLIC_KEY_FILE_NAME);
					r = fread(&mPublicKeyCount, sizeof(mPublicKeyCount), 1, fph);
					if (r == 1)
					{
						logMessage("Reading in %s public keys.\r\n", formatNumber(mPublicKeyCount));
						mAddresses = new PublicKeyData[mPublicKeyCount];
						mRecords = new PublicKeyRecord[mPublicKeyCount];
						r = fread(mAddresses, sizeof(PublicKeyData)*mPublicKeyCount, 1, fph);
						if (r == 1)
						{
							ret = true;
							logMessage("Successfully read all public keys into memory.\r\n");
						}
						else
						{
							logMessage("Failed to read all public keys into memory!\r\n");
							delete[]mAddresses;
							mAddresses = nullptr;
						}
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
			fclose(fph);

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

		virtual void printPublicKey(uint32_t index)
		{
			assert(index < mPublicKeyCount);
			PublicKeyRecord &r = mRecords[index];
			PublicKeyData &a = mAddresses[index];
			logMessage("==========================================================\r\n");

			logBitcoinAddress(a.address);
			logMessage("\r\n");
			logMessage("%s total transaction on this address.\r\n", formatNumber(int32_t(r.mTransactions.size())));

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

			uint32_t count = uint32_t(r.mTransactions.size());
			for (uint32_t i = 0; i<count; i++)
			{
				PublicKeyTransaction &t = r.mTransactions[i];
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
		FILE						*mTransactionFile;	// The data file which holds all transactions; too large to fit into memory
		uint32_t					mPublicKeyCount;
		PublicKeySet				mPublicKeys;		// the list of public keys...
		PublicKeyData				*mAddresses;
		PublicKeyRecord				*mRecords;			// The accumulated and collated data set for all public keys
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
