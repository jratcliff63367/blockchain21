#include "PublicKeyDatabase.h"
#include "CRC32.h"

#include <stdio.h>
#include <vector>
#include <unordered_set>
#include <assert.h>
#include <time.h>

#ifdef _MSC_VER
#pragma warning(disable:4100 4996)
#endif

namespace PUBLIC_KEY_DATABASE
{

#define MAXNUMERIC 32  // JWR  support up to 16 32 character long numeric formated strings
#define MAXFNUM    16

	static	char  gFormat[MAXNUMERIC*MAXFNUM];
	static int32_t    gIndex = 0;

	// This is a helper method for getting a formatted numeric output (basically having the commas which makes them easier to read)
	static const char * formatNumber(int32_t number) // JWR  format this integer into a fancy comma delimited string
	{
		char * dest = &gFormat[gIndex*MAXNUMERIC];
		gIndex++;
		if (gIndex == MAXFNUM) gIndex = 0;

		char scratch[512];

#ifdef _MSC_VER
		itoa(number, scratch, 10);
#else
		snprintf(scratch, 10, "%d", number);
#endif

		char *source = scratch;
		char *str = dest;
		uint32_t len = (uint32_t)strlen(scratch);
		if (scratch[0] == '-')
		{
			*str++ = '-';
			source++;
			len--;
		}
		for (uint32_t i = 0; i < len; i++)
		{
			int32_t place = (len - 1) - i;
			*str++ = source[i];
			if (place && (place % 3) == 0) *str++ = ',';
		}
		*str = 0;

		return dest;
	}


	static const char *getDateString(time_t t)
	{
		static char scratch[1024];
		struct tm *gtm = gmtime(&t);
		//	strftime(scratch, 1024, "%m, %d, %Y", gtm);
		sprintf(scratch, "%4d-%02d-%02d", gtm->tm_year + 1900, gtm->tm_mon + 1, gtm->tm_mday);
		return scratch;
	}

	static void printReverseHash(const uint8_t *hash)
	{
		if (hash)
		{
			for (uint32_t i = 0; i < 32; i++)
			{
				printf("%02x", hash[31 - i]);
			}
		}
		else
		{
			printf("NULL HASH");
		}
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


	class PublicKey : public BlockChain::OutputAddress
	{
	public:
		PublicKey(void)
		{
		}

		PublicKey(const BlockChain::OutputAddress &h) : BlockChain::OutputAddress(h)
		{
			mCRC = CRC32(address, sizeof(address), sizeof(address));
		}

		// Here the == operator is used to see if the hash values match
		bool operator==(const PublicKey &other) const
		{
			if (mCRC == other.mCRC) // if they have the same CRC value...
			{
				const BlockChain::OutputAddress &a = *this;
				const BlockChain::OutputAddress &b = other;
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
				for (uint32_t i = 0; i < count; i++)
				{
					TransactionInput ti(fph);
					mInputs.push_back(ti);
				}
				fread(&count, sizeof(count), 1, fph);
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
			printf("===============================================================================================================================\r\n");
			printf("TransactionHash: ");
			printReverseHash(mTransactionHash);
			printf("\r\n");
			printf("BlockNumber: %d\r\n", mBlockNumber);
			printf("TransactionVersionNumber: %d\r\n", mTransactionVersionNumber);
			printf("TransactionTime: %s\r\n", getDateString(time_t(mTransactionTime)));
			printf("InputCount: %d\r\n", mInputs.size());
			for (size_t i = 0; i < mInputs.size(); i++)
			{
				mInputs[i].echo();
			}
			printf("OutputCount: %d\r\n", mOutputs.size());
			for (size_t i = 0; i < mOutputs.size(); i++)
			{
				mOutputs[i].echo();
			}
			printf("===============================================================================================================================\r\n");
			printf("\r\n");
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

	typedef std::unordered_set< PublicKey >			PublicKeySet;			// The unordered set of all public keys
	typedef std::unordered_set< TransactionHash >	TransactionHashSet;		// The unordered set of all transactions; only contains the file seek offset

	const char *magicID = "PublicKeyDatabase";

	class PublicKeyDatabaseImpl : public PublicKeyDatabase
	{
	public:
		PublicKeyDatabaseImpl(void)
		{
			mPublicKeyCount = 0;
			mTransactionFile = fopen("TransactionFile.bin", "wb");
			if (mTransactionFile)
			{
				size_t slen = strlen(magicID);
				fwrite(magicID, slen + 1, 1, mTransactionFile); 
				fflush(mTransactionFile);
			}
		}

		virtual ~PublicKeyDatabaseImpl(void)
		{
			if (mTransactionFile)
			{
				fclose(mTransactionFile);
			}
		}

		virtual void addBlock(const BlockChain::Block *b)
		{
			if (!mTransactionFile)
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
					uint32_t addressIndex = getPublicKeyIndex(bo.addresses[0]);
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
		virtual void buildPublicKeyDatabase(void)
		{
			if (!mTransactionFile) return;
			fclose(mTransactionFile);
			printf("Processed %s transactions.\r\n", formatNumber(int32_t(mTransactions.size())));
			savePublicKeyFile();
#if 0
			mTransactionFile = nullptr;
			mTransactions.clear();		// We no longer need this hash-set of transaction hashes since we have rebased the data based the data based on transaction offset into the datafile
			if (!openTransactionsFile())
			{
				return;
			}
			uint64_t transactionOffset = uint64_t(ftell(mTransactionFile));
			Transaction t;
			while (readTransaction(t, transactionOffset))
			{
				t.echo();
				transactionOffset = uint64_t(ftell(mTransactionFile));
				// do stuff here...
			}
#endif
		}

		bool readTransaction(Transaction &t, uint64_t transactionOffset)
		{
			bool ret = false;

			_fseeki64(mTransactionFile, size_t(transactionOffset), SEEK_SET);
			uint64_t actual = uint64_t(ftell(mTransactionFile));
			if (actual == transactionOffset)
			{
				ret = t.read(mTransactionFile); // read this transaction 
			}

			return ret;
		}

		bool openTransactionsFile(void)
		{
			if (mTransactionFile) return false;
			mTransactionFile = fopen("TransactionFile.bin", "rb");
			if (mTransactionFile == nullptr) return false;
			size_t slen = strlen(magicID);
			char *temp = new char[slen + 1];
			size_t r = fread(temp, slen + 1, 1, mTransactionFile);
			bool ret = false;
			if (r == 1)
			{
				if (strcmp(temp, magicID) == 0)
				{
					ret = true;
				}
			}
			delete[]temp;
			return ret;
		}

		uint32_t getPublicKeyIndex(const BlockChain::OutputAddress &a)
		{
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
			FILE *fph = fopen("PublicKeys.bin", "wb");
			if (fph)
			{
				size_t slen = strlen(magicID);
				fwrite(magicID, slen + 1, 1, fph);
				uint32_t count = uint32_t(mPublicKeys.size());
				printf("Saving %s unique public keys from %s keys encountered; saving a total of %s\r\n", formatNumber(count), formatNumber(mPublicKeyCount), formatNumber(mPublicKeyCount - count));
				printf("Saving %s public key headers\r\n", formatNumber(count));
				fwrite(&count, sizeof(count), 1, fph);
				uint64_t baseLoc = ftell(fph);
				BlockChain::OutputAddress a;
				for (uint32_t i = 0; i < count; i++)
				{
					fwrite(&a, sizeof(a), 1, fph);
				}
				printf("Saving %s public key blocks\r\n", formatNumber(count));
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
		}

		virtual void release(void)
		{
			delete this;
		}
	private:
		uint32_t			mPublicKeyCount;
		PublicKeySet		mPublicKeys;		// the list of public keys...
		TransactionHashSet	mTransactions;		// The list of all transaction hashes
		FILE				*mTransactionFile;	// The data file which holds all transactions; too large to fit into memory
	};

}

PublicKeyDatabase * PublicKeyDatabase::create(void)
{
	PUBLIC_KEY_DATABASE::PublicKeyDatabaseImpl *p = new PUBLIC_KEY_DATABASE::PublicKeyDatabaseImpl;
	return static_cast<PublicKeyDatabase *>(p);
}
