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
#define DUST_VALUE ONE_MBTC

// how old, in seconds, before an input is considered a 'zombie'
#define ZOMBIE_TIME (365*4)

#ifdef _MSC_VER
#pragma warning(disable:4100 4996 4189 4456)
#endif

namespace PUBLIC_KEY_DATABASE
{

	enum ValueType
	{
		VT_MICRO_BIT,    // 0.0001
		VT_MILI_BIT,     // 0.001
		VT_CENTI_BIT,    // 0.01
		VT_TENTH,		 // 0.1
		VT_QUARTER,		 // 0.25
		VT_BTC,			 // 1
		VT_TEN_BTC,		 // 10
		VT_HUNDRED_BTC,  // 100
		VT_THOUSAND_BTC, // 1000
		VT_TEN_THOUSAND_BTC, // 10,000
        VT_ONE_HUNDRED_THOUSAND_BTC, // 100,000
        VT_ONE_MILLION_BTC, // 1,000,000
		VT_LAST_ENTRY
	};

	double getValueTypeValue(ValueType t)
	{
		double ret = 0;
		switch ( t )
		{
			case VT_MICRO_BIT:    // 0.0001
				ret = 0.0001;
				break;
			case VT_MILI_BIT:     // 0.001
				ret = 0.001;
				break;
			case VT_CENTI_BIT:    // 0.01
				ret = 0.01;
				break;
			case VT_TENTH:		 // 0.1
				ret = 0.1;
				break;
			case VT_QUARTER:		 // 0.25
				ret = 0.25;
				break;
			case VT_BTC:			 // 1
				ret = 1;
				break;
			case VT_TEN_BTC:		 // 10
				ret = 10;
				break;
			case VT_HUNDRED_BTC:  // 100
				ret = 100;
				break;
			case VT_THOUSAND_BTC: // 1000
				ret = 1000;
				break;
			case VT_TEN_THOUSAND_BTC:
				ret = 10000;
				break;
            case VT_ONE_HUNDRED_THOUSAND_BTC:
                ret = 100000;
                break;
            case VT_ONE_MILLION_BTC:
                ret = 1000000;
                break;
            default:
                assert(0);
                break;
		}
		return ret;
	}

	const char * getValueTypeLabel(ValueType type)
	{
		const char *ret = "UNKNOWN";

		switch (type)
		{
			case VT_MICRO_BIT:    // 0.0001
				ret = "0.0001";
				break;
			case VT_MILI_BIT:     // 0.001
				ret = "0.001";
				break;
			case VT_CENTI_BIT:    // 0.01
				ret = "0.01";
				break;
			case VT_TENTH:		 // 0.1
				ret = "0.1";
				break;
			case VT_QUARTER:		 // 0.25
				ret = "0.25";
            	break;
			case VT_BTC:			 // 1
				ret = "1btc";
				break;
			case VT_TEN_BTC:		 // 10
				ret = "10btc";
				break;
			case VT_HUNDRED_BTC:  // 100
				ret = "100btc";
				break;
			case VT_THOUSAND_BTC: // 1000
				ret = "1,000btc";
				break;
			case VT_TEN_THOUSAND_BTC:
				ret = "10,000btc";
				break;
            case VT_ONE_HUNDRED_THOUSAND_BTC:
                ret = "100,000btc";
                break;
            case VT_ONE_MILLION_BTC:
                ret = "1,000,000btc";
                break;
             default:
                assert(0);
                break;
		}
		return ret;
	}

	struct ValueEntry
	{
		void init(ValueType t)
		{
			mType = t;
			mCount = 0;
			mTotalValue = 0;
			mValue = getValueTypeValue(mType);
			mLabel = getValueTypeLabel(mType);
		}

		void addValue(uint64_t v)
		{
			double dv = double(v) / ONE_BTC;
			addValue(v);
		}


		void addValue(double v)
		{
			mCount++;
			mTotalValue += v;
		}

		ValueType	mType;				// type of value
		double		mValue;				// amount of value
		uint32_t	mCount;				// number of transactions within this value range
		double		mTotalValue;		// total value of transactions within this range
		const char	*mLabel;
	};

	struct ValueEntryTable
	{
		ValueEntryTable(void)
		{
			init();
		}

		void init(void)
		{
			mTable[VT_MICRO_BIT].init(VT_MICRO_BIT);
			mTable[VT_MILI_BIT].init(VT_MILI_BIT);
			mTable[VT_CENTI_BIT].init(VT_CENTI_BIT);
			mTable[VT_TENTH].init(VT_TENTH);
			mTable[VT_QUARTER].init(VT_QUARTER);
			mTable[VT_BTC].init(VT_BTC);
			mTable[VT_TEN_BTC].init(VT_TEN_BTC);
			mTable[VT_HUNDRED_BTC].init(VT_HUNDRED_BTC);
			mTable[VT_THOUSAND_BTC].init(VT_THOUSAND_BTC);
			mTable[VT_TEN_THOUSAND_BTC].init(VT_TEN_THOUSAND_BTC);
            mTable[VT_ONE_HUNDRED_THOUSAND_BTC].init(VT_ONE_HUNDRED_THOUSAND_BTC);
            mTable[VT_ONE_MILLION_BTC].init(VT_ONE_MILLION_BTC);
		}

		void addValue(uint64_t v)
		{
			double dv = double(v) / ONE_BTC;
			addValue(dv);
		}

		void addValue(double v)
		{
			bool found = false;
			double prev = 0;
			for (uint32_t i = 0; i < (VT_LAST_ENTRY-1); i++)
			{
				if (v >= prev && v < mTable[i].mValue)
				{
					found = true;
					mTable[i].addValue(v);
					break;
				}
				prev = mTable[i].mValue;
			}
			if (!found)
			{
				assert(v >= 1000000);
				mTable[VT_ONE_MILLION_BTC].addValue(v);
			}
		}

		void outputHeader(FILE_INTERFACE *fph)
		{
			for (uint32_t i = 0; i < VT_LAST_ENTRY; i++)
			{
				fi_fprintf(fph, "\"%s count\",", mTable[i].mLabel);
			}
			for (uint32_t i = 0; i < VT_LAST_ENTRY; i++)
			{
				fi_fprintf(fph, "\"%s value\",", mTable[i].mLabel);
			}
		}

		void outputValue(FILE_INTERFACE *fph)
		{
			for (uint32_t i = 0; i < VT_LAST_ENTRY; i++)
			{
				fi_fprintf(fph, "%d,", mTable[i].mCount);
			}
			for (uint32_t i = 0; i < VT_LAST_ENTRY; i++)
			{
				fi_fprintf(fph, "%f,", mTable[i].mTotalValue);
			}
		}


		ValueEntry	mTable[VT_LAST_ENTRY];
	};



#define MAXIMUM_DAYS (365*10)	// Leave room for 10 years of days

	enum AgeRank
	{
		AR_ONE_DAY,
		AR_ONE_WEEK,			// 2- 7 days
		AR_ONE_MONTH,			// 2 to 4 weeks
		AR_THREE_MONTHS,		// one month to three months
		AR_SIX_MONTHS,			// six months to one year
		AR_ONE_YEAR,			// one-to-two years
		AR_TWO_YEARS,			// two to three years
		AR_THREE_YEARS,
		AR_FOUR_YEARS,
		AR_ZOMBIE,				// over 3 years
		AR_LAST
	};


	class AgeStat
	{
	public:
		void init(AgeRank r)
		{
			switch (r)
			{
				case AR_ONE_DAY:
					mDays = 1;
					mLabel = "One Day";
					mCount = 0;
					mValue = 0;
					break;
				case AR_ONE_WEEK:
					mDays = 7;
					mLabel = "Past Week";
					mCount = 0;
					mValue = 0;
					break;
				case AR_ONE_MONTH:
					mDays = 30;
					mLabel = "Past Month";
					mCount = 0;
					mValue = 0;
					break;
				case AR_THREE_MONTHS:
					mDays = 365 / 4;
					mLabel = "One to Three Months";
					mCount = 0;
					mValue = 0;
					break;
				case AR_SIX_MONTHS:
					mDays = 365 / 2;
					mLabel = "Four to Six Months";
					mCount = 0;
					mValue = 0;
					break;
				case AR_ONE_YEAR:
					mDays = 365;
					mLabel = "Six Months to One Year";
					mCount = 0;
					mValue = 0;
					break;
				case AR_TWO_YEARS:
					mDays = 365 * 2;
					mLabel = "One to Two Years";
					mCount = 0;
					mValue = 0;
					break;
				case AR_THREE_YEARS:
					mDays = 365 * 3;
					mLabel = "Two to Three Years";
					mCount = 0;
					mValue = 0;
					break;
				case AR_FOUR_YEARS:
					mDays = 365 * 4;
					mLabel = "Three to Four Years";
					mCount = 0;
					mValue = 0;
					break;
				case AR_ZOMBIE:
					mDays = 365 * 1000;
					mLabel = "Over Four Years";
					mCount = 0;
					mValue = 0;
					break;
			}
		}

		AgeRank		mRank;
		uint32_t	mDays;
		const char *mLabel;
		uint32_t	mCount;
		double		mValue;
	};
	class DailyStatistics
	{
	public:

		DailyStatistics(void)
		{
			memset(this, sizeof(DailyStatistics), 0);
			for (uint32_t i = 0; i < AR_LAST; i++)
			{
				mAgeStats[i].init((AgeRank)i);
			}
			mValueEntryTable.init();
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
		uint64_t	mMaxInputValue;							// Maximum input value for this day
		uint32_t	mTotalInputScriptLength;				// Total size of all input scripts for this day
		uint32_t	mMaxInputScriptLength;					// Maximum input script length on this day

		double		mTotalOutputValue;						// Total value of all outputs for this day
		uint64_t	mMaxOutputValue;						// Maximum output value for this day
		uint32_t	mTotalOutputScriptLength;				// Total size of all output scripts for this day
		uint32_t	mMaxOutputScriptLength;					// Maximum output script length on this day

		uint32_t	mCurrentBlock;							// The current block for this day
		uint32_t	mTransactionBlockCount;					// How many transactions are in the current block
		uint32_t	mBlockCount;							// Number of blocks on this day
		uint32_t	mMaxTransactionBlockCount;				// Maximum number of transactions in a block

		uint32_t	mMaxInputAge;							// old input for this day.

		uint32_t	mDustCount;								// number of dust transactions on this day

		uint32_t	mZombieInputCount;						// Number of times an input more than 3 years old was encountered
		double		mZombieInputValue;						// Total value in BTC that was more than 3 years old
		double		mZombieScore;

		uint32_t	mUTXOCount;					// total number of unspent transaction outputs
		double		mUTXOValue;					// total value of all unspent transaction outputs

		uint32_t	mEarlyCount;		// Number of unspent transaction outputs from 2009-2010
		double		mEarlyValue;		// Total vaule of unspent transaction outputs from 2009-2010

		AgeStat		mAgeStats[AR_LAST];			// UTXO by age stats


		ValueEntryTable	mValueEntryTable;
	};


	const uint32_t BITCOIN_START_DATE = 1231001362;

	uint32_t getAgeInDays(uint32_t timestamp)
	{
		uint32_t diff = timestamp - BITCOIN_START_DATE;
		uint32_t days = diff / SECONDS_PER_DAY;
		return days;
	}

	uint32_t getAgeInDays(uint32_t timestamp,uint32_t referenceDate)
	{
		uint32_t diff = 0;
		if (referenceDate > timestamp)
		{
			diff = referenceDate - timestamp;
		}
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


	bool isEarly(uint32_t timeStamp)
	{
		bool ret = false;

		static char scratch[1024];
		time_t t(timeStamp);
		struct tm *gtm = gmtime(&t);
		uint32_t year = gtm->tm_year + 1900;
		if (year == 2009 || year == 2010 )
		{
			ret = true;
		}

		return ret;
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
		TransactionHash(void) : mFileOffset(0), mTimeStamp(0)
		{
		}

		TransactionHash(const Hash256 &h) : Hash256(h), mFileOffset(0), mTimeStamp(0)
		{
		}

		// Here the == operator is used to see if the hash values match
		bool operator==(const TransactionHash &other) const
		{
			const Hash256 &a = *this;
			const Hash256 &b = other;
			return a == b;
		}

		void setFileOffset(uint64_t fileOffset)
		{
			mFileOffset = fileOffset;
		}

		uint64_t getFileOffset(void) const
		{
			return mFileOffset;
		}

		void setTimeStamp(uint32_t t)
		{
			mTimeStamp = t;
		}
		uint32_t getTimeStamp(void) const
		{
			return mTimeStamp;
		}
	private:
		uint64_t			mFileOffset;	// The location in the file for this transaction
		uint32_t			mTimeStamp;
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
		TransactionInput(const BlockChain::BlockInput &bi, uint64_t fileOffset,uint32_t timeStamp,uint64_t inputValue)
		{
			mTransactionFileOffset	= fileOffset;
			mTransactionIndex		= bi.transactionIndex;
			mInputValue				= inputValue;
			mResponseScriptLength = bi.responseScriptLength;
			mTimeStamp = timeStamp;
		}

		TransactionInput(FILE_INTERFACE *fph)
		{
			fi_fread(&mTransactionFileOffset, sizeof(mTransactionFileOffset), 1, fph);
			fi_fread(&mTransactionIndex, sizeof(mTransactionIndex), 1, fph);
			fi_fread(&mInputValue, sizeof(mInputValue), 1, fph);
			fi_fread(&mResponseScriptLength, sizeof(mResponseScriptLength), 1, fph);
			fi_fread(&mTimeStamp, sizeof(mTimeStamp), 1, fph);
		}

		void save(FILE_INTERFACE *fph)
		{
			fi_fwrite(&mTransactionFileOffset, sizeof(mTransactionFileOffset), 1, fph);
			fi_fwrite(&mTransactionIndex, sizeof(mTransactionIndex), 1, fph);
			fi_fwrite(&mInputValue, sizeof(mInputValue), 1, fph);
			fi_fwrite(&mResponseScriptLength, sizeof(mResponseScriptLength), 1, fph);
			fi_fwrite(&mTimeStamp, sizeof(mTimeStamp), 1, fph);
		}

		void echo(void)
		{

		}

		uint64_t	mTransactionFileOffset;			// Which transaction this input refers to (0 means coinbase)
		uint32_t	mTransactionIndex;				// Which output forms this input
		uint32_t	mResponseScriptLength;			// The length of the response script
		uint64_t	mInputValue;					// The input value
		uint32_t	mTimeStamp;
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

		void addInput(const BlockChain::BlockInput &bi, uint64_t fileOffset,uint32_t timeStamp,uint64_t inputValue)
		{
			TransactionInput ti(bi, fileOffset,timeStamp,inputValue);
			mInputs.push_back(ti);
		}

		void addOutput(const BlockChain::BlockOutput &bo,uint32_t addressIndex)
		{
			TransactionOutput to(bo,addressIndex);
			mOutputs.push_back(to);
		}

		void echo(void)
		{
			logMessage("===============================================================================================================================\n");
			logMessage("TransactionHash: ");
			printReverseHash(mTransactionHash);
			logMessage("\n");
			logMessage("BlockNumber: %d\n", mBlockNumber);
			logMessage("TransactionVersionNumber: %d\n", mTransactionVersionNumber);
			logMessage("TransactionTime: %s\n", getDateString(time_t(mTransactionTime)));
			logMessage("InputCount: %d\n", mInputs.size());
			for (size_t i = 0; i < mInputs.size(); i++)
			{
				mInputs[i].echo();
			}
			logMessage("OutputCount: %d\n", mOutputs.size());
			for (size_t i = 0; i < mOutputs.size(); i++)
			{
				mOutputs[i].echo();
			}
			logMessage("===============================================================================================================================\n");
			logMessage("\n");
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

class UTXO
{
public:
	UTXO(void)
	{

	}
	UTXO(uint64_t fileOffset, uint64_t inputIndex) : mFileOffset(fileOffset), mInputIndex(inputIndex)
	{

	}

	bool operator==(const UTXO &other) const
	{
		return other.mFileOffset == mFileOffset && other.mInputIndex == mInputIndex;
	}

	uint64_t getHash(void) const
	{
		return mFileOffset ^ mInputIndex;
	}

	uint64_t	mFileOffset;			// The file offset where the transaction is located
	uint64_t	mInputIndex;			// The index number of this output
};

class UTXOSTAT
{
public:
	UTXOSTAT(void)
	{
		mValue = 0;
		mTimeStamp = 0;
	}
	UTXOSTAT(uint64_t value, uint32_t timeStamp)
	{
		mValue = value;
		mTimeStamp = timeStamp;
	}
	uint64_t	mValue;				// The value in this unspent transaction output
	uint32_t	mTimeStamp;			// The date of this unspent transaction output
};

namespace std
{
	template <>
	struct hash<UTXO>
	{
		std::size_t operator()(const UTXO &k) const
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
	typedef std::unordered_map< UTXO, uint64_t > UTXOMap;
	typedef std::unordered_map< UTXO, UTXOSTAT > UTXOStatMap;

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
					logMessage("A pre-processed transactions database already exists!\n");
					logMessage("Are you sure you want to delete it and start over?\n");
					logMessage("Press 'y' to continue, any other key to cancel.\n");
					key = getKey();
				}
				if (key == 'y')
				{
					fi_deleteFile(PUBLIC_KEY_RECORDS_FILE_NAME);
					mTransactionFile = fi_fopen(TRANSACTION_FILE_NAME, "wb+", nullptr, 0, false);
					if (mTransactionFile)
					{
						size_t slen = strlen(magicID);
						fi_fwrite(magicID, slen + 1, 1, mTransactionFile);
						mTransactionFileCountSeekLocation = uint32_t(fi_ftell(mTransactionFile));
						fi_fwrite(&mTransactionCount, sizeof(mTransactionCount), 1, mTransactionFile); // save the number of transactions
						fi_fflush(mTransactionFile);
						mPublicKeyFile = fi_fopen(PUBLIC_KEY_FILE_NAME, "wb+", nullptr, 0, false);
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
							logMessage("Failed to open file '%s' for write access.\n", PUBLIC_KEY_FILE_NAME);
						}
					}
					else
					{
						logMessage("Failed to open file '%s' for write access.\n", TRANSACTION_FILE_NAME);
					}
				}
			}
		}

		virtual ~PublicKeyDatabaseImpl(void)
		{
			logMessage("~PublicKeyDatabaseImpl destructor\n");
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
					uint32_t timeStamp = 0;
					uint64_t inputValue = 0;
					if (found == mTransactions.end())
					{
						timeStamp = b->timeStamp; // if it's a coinbase transaction, we just use the block time as the timestamp
						if (bi.transactionIndex != 0xFFFFFFFF) // If it is not a coinbase transaction, then assert
						{
							assert(0); // we should always be able to find the previous transaction!
						}
					}
					else
					{
						fileOffset = (*found).getFileOffset();
						timeStamp = (*found).getTimeStamp();
						UTXO utxo(fileOffset, bi.transactionIndex);
						UTXOMap::iterator found = mUTXO.find(utxo);
						if (found != mUTXO.end())
						{
							inputValue = (*found).second;
							mUTXO.erase(found); // we can now remove it since it has been consumed
						}
						else
						{
							logMessage("Failed to locate unspent transaction output.\r\n");
						}
					}
					t.addInput(bi, fileOffset,timeStamp, inputValue);
				}

				// Each output gets added to the UTXO hash map
				for (uint32_t i = 0; i < bt.outputCount; i++)
				{
					const BlockChain::BlockOutput &bo = bt.outputs[i];
					uint32_t addressIndex = getPublicKeyIndex(bo.asciiAddress);
					t.addOutput(bo,addressIndex);
					// Add it to the UTXO set
					UTXO utxo(fileOffset, i);
					mUTXO[utxo] = bo.value;			// Crash occurred here?  Why?
				}

				t.save(mTransactionFile);
				Hash256 h(bt.transactionHash);
				TransactionHash th(h);
				th.setFileOffset(fileOffset);
				th.setTimeStamp(b->timeStamp);

				TransactionHashSet::iterator found = mTransactions.find(th);
				if (found != mTransactions.end() )
				{
					logMessage("Encountered the same transaction hash twice; this appears to be a bug and must be fixed! Ignoring second occurence for now.\n");
					logMessage("DuplicateHash:");
					printReverseHash((const uint8_t *)&th.mWord0);
					logMessage("\n");
				}
				else
				{
					mTransactionCount++;	// increment the transaction count
					mTransactions.insert(th);	// Add it to the transaction hash table; so we can convert from a transaction hash to a file offset quickly and efficiently
				}
			}
			fi_fflush(mTransactionFile);

			if ((b->blockIndex % 10000) == 0)
			{
				closePublicKeyFile(true); //
			}
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
				closePublicKeyFile(false);
				mTransactionFile = nullptr;
				logMessage("Clearing transactions container\n");
				mTransactions.clear();		// We no longer need this hash-set of transaction hashes since we have rebased the data based the data based on transaction offset into the datafile
				logMessage("Clearing UTXO container\n");
				mUTXO.clear();

				logMessage("Clearing PublicKeys container\n");
				mPublicKeys.clear();		// We no longer needs this hash set, so free up the memory
				mAnalyze = true;
				logMessage("Opening the transactions file\n");
				openTransactionsFile();
				logMessage("Loading the PublicKey address file\n");
				loadPublicKeyFile();
			}
			logMessage("Creating PublicKey records data  set.\n");
			PublicKeyRecord *records = new PublicKeyRecord[mPublicKeyCount];
			for (uint32_t i = 0; i < mPublicKeyCount; i++)
			{
				records[i].mIndex = i; // assign the array index
			}
			logMessage("Building PublicKey records.\n");
			uint32_t transactionCount = 0;
			uint64_t transactionOffset = uint64_t(fi_ftell(mTransactionFile));
			Transaction t;
			while (readTransaction(t, transactionOffset))
			{
				transactionCount++;
				if ((transactionCount % 10000) == 0)
				{
					logMessage("Processing transaction %s\n", formatNumber(transactionCount));
				}
				uint64_t toffset = transactionOffset; // the base transaction offset
				transactionOffset = uint64_t(fi_ftell(mTransactionFile));
				processTransaction(t,toffset,records);
				// do stuff here...
			}
			logMessage("Public Key Records built.\n");
			savePublicKeyRecords(records); // save the records to disk!
			logMessage("Finished saving public records, now deleting them.\n");
			delete[]records;
			logMessage("Public record deletion now complete.\n");
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
							logMessage("WARNING! Encountered index to public key #%s but the maximum number of public keys we have is %s\n", formatNumber(to.mIndex), formatNumber(mPublicKeyCount));
						}
					}
					else
					{
						logMessage("Invalid transaction index of %d; maximum outputs in this transaction are %d\n", ti.mTransactionIndex, inputTransaction.mOutputs.size());
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
					logMessage("WARNING! Encountered index to public key #%s but the maximum number of public keys we have is %s\n", formatNumber(to.mIndex), formatNumber(mPublicKeyCount));
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
				logMessage("Failed to open transaction file '%s' for read access.\n", TRANSACTION_FILE_NAME);
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
					logMessage("Successfully opened the transaction file '%s' for read access.\n", TRANSACTION_FILE_NAME);
					fi_fread(&mTransactionCount, sizeof(mTransactionCount), 1, mTransactionFile);
					assert(mTransactionCount); // if this is zero then the transaction file didn't close cleanly, we could dervive this value if necessary.
					mFirstTransactionOffset = fi_ftell(mTransactionFile);
				}
				else
				{
					logMessage("Not a valid transaction invalid header block.\n");
				}
			}
			else
			{
				logMessage("Not a valid transaction file failed to read header.\n");
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
			logMessage("Saving %s public key records; this is the fully collated set of transactions corresponding to each unique public key address.\n", formatNumber(mPublicKeyCount));
			FILE_INTERFACE *fph = fi_fopen(PUBLIC_KEY_RECORDS_FILE_NAME, "wb+", nullptr, 0, false);
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
				logMessage("All records now saved to file '%s'\n", PUBLIC_KEY_RECORDS_FILE_NAME);
			}
		}

		// Close the unique public keys file
		void closePublicKeyFile(bool isCheckPoint)
		{
			assert(mTransactionCount == uint32_t(mTransactions.size()));
			assert(mPublicKeyCount == uint32_t(mPublicKeys.size()));

			// Write out the total number of transactions and then close the transactions file
			if (mTransactionFile)
			{
				uint64_t curLoc = fi_ftell(mTransactionFile);
				if (isCheckPoint)
				{
					logMessage("Checkpointing the transaction file which contains %s transactions.\n", formatNumber(mTransactionCount));
				}
				else
				{
					logMessage("Closing the transaction file which contains %s transactions.\n", formatNumber(mTransactionCount));
				}
				fi_fseek(mTransactionFile, mTransactionFileCountSeekLocation, SEEK_SET);
				fi_fwrite(&mTransactionCount, sizeof(mTransactionCount), 1, mTransactionFile);
				if (isCheckPoint)
				{
					fi_fseek(mTransactionFile, curLoc, SEEK_SET);
				}
				else
				{
					fi_fclose(mTransactionFile);
					mTransactionFile = nullptr;
				}
			}
			else
			{
				assert(0);
			}

			logMessage("Processed %s transactions with %s unique public keys.\n", formatNumber(int32_t(mTransactionCount)), formatNumber(int32_t(mPublicKeyCount)));

			if (mPublicKeyFile)
			{
				uint64_t curLoc = fi_ftell(mPublicKeyFile);
				if (isCheckPoint)
				{
					logMessage("Checkpointing the PublicKeys file\n");
				}
				else
				{
					logMessage("Closing the PublicKeys file\n");
				}
				fi_fseek(mPublicKeyFile, mPublicKeyFileCountSeekLocation, SEEK_SET);
				fi_fwrite(&mPublicKeyCount, sizeof(mPublicKeyCount), 1, mPublicKeyFile);
				if (isCheckPoint)
				{
					fi_fseek(mPublicKeyFile, curLoc, SEEK_SET);
				}
				else
				{
					fi_fclose(mPublicKeyFile);
					mPublicKeyFile = nullptr;
				}
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
				logMessage("Failed to open public key file '%s' for read access.\n", PUBLIC_KEY_FILE_NAME);
				return false;
			}
			size_t slen = strlen(magicID);
			char *temp = new char[slen + 1];
			size_t r = fi_fread(temp, slen + 1, 1, mAddressFile);
			if (r == 1)
			{
				if (strcmp(temp, magicID) == 0)
				{
					logMessage("Successfully opened the public key file '%s' for read access.\n", PUBLIC_KEY_FILE_NAME);
					r = fi_fread(&mPublicKeyCount, sizeof(mPublicKeyCount), 1, mAddressFile);
					if (r == 1)
					{
						logMessage("Reading in %s public keys.\n", formatNumber(mPublicKeyCount));
						mAddresses = (PublicKeyData *)fi_getCurrentMemoryLocation(mAddressFile);
					}
					else
					{
						logMessage("Failed to read from public key file.\n");
					}
				}
				else
				{
					logMessage("Not a valid header block.\n");
				}
			}
			else
			{
				logMessage("Not a valid file failed to read header.\n");
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
				logMessage("Failed to open public key file '%s' for read access.\n", PUBLIC_KEY_RECORDS_FILE_NAME);
				return false;
			}
			size_t slen = strlen(magicID);
			char *temp = new char[slen + 1];
			size_t r = fi_fread(temp, slen + 1, 1, mPublicKeyRecordFile);
			if (r == 1)
			{
				if (strcmp(temp, magicID) == 0)
				{
					logMessage("Successfully opened the public key records file '%s' for read access.\n", PUBLIC_KEY_RECORDS_FILE_NAME);
					uint32_t publicKeyCount = 0;
					r = fi_fread(&publicKeyCount, sizeof(publicKeyCount), 1, mPublicKeyRecordFile);
					if (r == 1)
					{
						assert(publicKeyCount); // if the public key count is zero; this probably indicates that the file did not close cleanly on creation. We could derive the count if necessary...
						assert(publicKeyCount == mPublicKeyCount);
						mPublicKeyCount = publicKeyCount;
						logMessage("Initializing pointer tables for %s public keys records\n", formatNumber(mPublicKeyCount));
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
						logMessage("Failed to read from public key records file.\n");
					}
				}
				else
				{
					logMessage("Not a valid header block.\n");
				}
			}
			else
			{
				logMessage("Not a valid file failed to read header.\n");
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
			logMessage("==========================================================\n");

			logBitcoinAddress(a.address);
			logMessage("\n");
			logMessage("%s total transaction on this address.\n", formatNumber(int32_t(r.mCount)));

			uint64_t totalSend = r.getTotalSend();
			if (totalSend)
			{
				logMessage("Total Value Sent: %0.2f\n", float(totalSend) / ONE_BTC);
			}
			logMessage("Total Value Received: %0.2f\n", float(r.getTotalReceive()) / ONE_BTC);
			logMessage("Balance: %0.2f\n", float(r.getBalance()) / ONE_BTC);
			uint32_t lastSendTime = r.getLastSendTime();
			if (lastSendTime)
			{
				logMessage("LastSend: %s\n", getTimeString(lastSendTime));
			}
			uint32_t lastReceiveTime = r.getLastReceiveTime();
			if (lastReceiveTime)
			{
				logMessage("LastReceive: %s\n", getTimeString(lastReceiveTime));
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
				logMessage("%10s : %10s : %0.2f \n", prefix, getTimeString(t.mTimeStamp), float(t.mValue) / ONE_BTC );
			}


			logMessage("==========================================================\n");
			logMessage("\n");
		}

		void initByTime(uint32_t timeStamp)
		{
			logMessage("Computing balances up to this date: %s\n", getTimeString(timeStamp));
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
			logMessage("Finished computing balances for %s public keys.\n", formatNumber(mPublicKeyCount));
			logMessage("Sorting by balance.\n");
			SortByBalance sbb;
			sbb.heapSort((void **)(mPublicKeyRecordSorted), mPublicKeyCount);
			FILE *fph = fopen(reportFileName, "wb+");
			if (fph)
			{
				fprintf(fph, "PublicKey,Balance,Age\n");
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
					fprintf(fph, "%s,%0.2f,%d\n", getBitcoinAddressAscii(a.address), (float)pkrf.mBalance / ONE_BTC, pkrf.mDaysOld);
				}
				fclose(fph);
			}
			else
			{
				logMessage("Failed to open report file '%s' for write access\n");
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
			mZombieInputs.clear();
			time_t curTime;
			time(&curTime);		// get the current 'real' time; if we go past it, we stop..
			mLastDay = 0;
			seekFirstTransaction();
			uint32_t transactionCount = 0;
			uint64_t transactionOffset = uint64_t(fi_ftell(mTransactionFile));
			Transaction t;
			while (readTransaction(t, transactionOffset))
			{
				transactionCount++;
				if ((transactionCount % 10000) == 0)
				{
					logMessage("Processing transaction %s\n", formatNumber(transactionCount));
				}
				uint64_t toffset = transactionOffset; // the base transaction offset
				transactionOffset = uint64_t(fi_ftell(mTransactionFile));
				computeTransactionStatistics(t,toffset);
			}


			{
				logMessage("Generating Value Distribution report.\r\n");
				FILE_INTERFACE *fph = fi_fopen("ValueDistribution.csv", "wb", nullptr, 0, false);
				if (fph)
				{
					fi_fprintf(fph, "Date,");
					ValueEntryTable vt;
					vt.outputHeader(fph);
					fi_fprintf(fph,"\r\n");
					for (uint32_t i = 0; i < MAXIMUM_DAYS; i++)
					{
						if (noMoreDays(i))
						{
							break;
						}

						DailyStatistics &d = mDailyStatistics[i];

						if (d.mTimeStamp)
						{
							fi_fprintf(fph, "%s,", getDateString(d.mTimeStamp));	// Date
							d.mValueEntryTable.outputValue(fph);
							fi_fprintf(fph, "\r\n");
						}
					}
					fi_fclose(fph);
				}
			}

			FILE_INTERFACE *fph = fi_fopen(reportFileName, "wb", nullptr, 0, false);
			if (fph)
			{
				logMessage("Generating daily transactions report to file '%s'\n", reportFileName);
				fi_fprintf(fph,"Date");

				fi_fprintf(fph, ",BlockCount");
				fi_fprintf(fph, ",DustCount");
				fi_fprintf(fph, ",TotalTransactionCount");
				fi_fprintf(fph, ",AverageTransactionCount");
				fi_fprintf(fph, ",MaxTransactionCount");

				fi_fprintf(fph, ",TotalTransactionSize");
				fi_fprintf(fph, ",AverageTransactionSize");

				fi_fprintf(fph, ",TotalInputCount");
				fi_fprintf(fph, ",AverageInputCount");
				fi_fprintf(fph, ",MaxInputCount");
				fi_fprintf(fph, ",TotalInputValue");
				fi_fprintf(fph, ",AverageInputValue");
				fi_fprintf(fph, ",MaxInputValue");
				fi_fprintf(fph, ",TotalInputScriptLength");
				fi_fprintf(fph, ",AverageInputScriptLength");

				fi_fprintf(fph, ",TotalOutputCount");
				fi_fprintf(fph, ",AverageOutputCount");
				fi_fprintf(fph, ",MaxOutputCount");
				fi_fprintf(fph, ",TotalOutputValue");
				fi_fprintf(fph, ",AverageOutputValue");
				fi_fprintf(fph, ",MaxOutputValue");
				fi_fprintf(fph, ",TotalOutputScriptLength");
				fi_fprintf(fph, ",AverageOutputScriptLength");


				fi_fprintf(fph, ",MaxInputDaysOld");

				fi_fprintf(fph, ",ZombieInputCount");
				fi_fprintf(fph, ",ZombieInputValue");
				fi_fprintf(fph, ",ZombieScore");

				fi_fprintf(fph, ",UTXOCount");
				fi_fprintf(fph, ",UTXOValue");

				fi_fprintf(fph, ",EarlyCount");
				fi_fprintf(fph, ",EarlyValue");


				{
					DailyStatistics &d = mDailyStatistics[0];
					for (uint32_t i = 0; i < AR_LAST; i++)
					{
						fi_fprintf(fph, ",\"%s Count\"", d.mAgeStats[i].mLabel);
					}
					for (uint32_t i = 0; i < AR_LAST; i++)
					{
						fi_fprintf(fph, ",\"%s Value\"", d.mAgeStats[i].mLabel);
					}
				}

				fi_fprintf(fph, "\n");


				for (uint32_t i = 0; i < MAXIMUM_DAYS; i++)
				{
					if (noMoreDays(i))
					{
						break;
					}
					DailyStatistics &d = mDailyStatistics[i];

					if (d.mTimeStamp)
					{
						fi_fprintf(fph, "%s",	getDateString(d.mTimeStamp));	// Date
						fi_fprintf(fph, ",%d",	d.mBlockCount);										// Blocks on this day
						fi_fprintf(fph, ",%d", d.mDustCount);
						fi_fprintf(fph, ",%d",	d.mTransactionCount);								// Number of transactions on this day
						fi_fprintf(fph, ",%f",	(double)d.mTransactionCount / (double)d.mBlockCount);				// Average number of transactions per block
						fi_fprintf(fph, ",%d",  d.mMaxTransactionBlockCount);						// Most transactions in a block
						fi_fprintf(fph, ",%d",	d.mTransactionSize);								// Total size of all transactions on this day
						fi_fprintf(fph, ",%f",  (double)d.mTransactionSize / (double)d.mTransactionCount);			// Average size of a transaction on this day

						fi_fprintf(fph, ",%d", d.mInputCount);										// Total number of inputs on this day.
						fi_fprintf(fph, ",%f", (double)d.mInputCount / (double)d.mTransactionCount);	// Average number of inputs per transaction
						fi_fprintf(fph, ",%d", d.mMaxInputCount);									// Maximum number of inputs on a transaction this day
						fi_fprintf(fph, ",%f", d.mTotalInputValue);									// Total input value
						fi_fprintf(fph, ",%f", d.mTotalInputValue / (double)d.mTransactionCount);	// Average input value per transaction
						fi_fprintf(fph, ",%f", (double)d.mMaxInputValue / ONE_BTC);					// Maximum input value on this day
						fi_fprintf(fph, ",%d", d.mTotalInputScriptLength);
						fi_fprintf(fph, ",%f", (double)d.mTotalInputScriptLength / (double)d.mInputCount);

						fi_fprintf(fph, ",%d", d.mOutputCount);										// Total number of outputs on this day.
						fi_fprintf(fph, ",%f", (double)d.mOutputCount / (double)d.mTransactionCount);	// Average number of outputs per transaction
						fi_fprintf(fph, ",%d", d.mMaxOutputCount);									// Maximum number of outputs on a transaction this day
						fi_fprintf(fph, ",%f", d.mTotalOutputValue);									// Total output value
						fi_fprintf(fph, ",%f", d.mTotalOutputValue / (double)d.mTransactionCount);	// Average output value per transaction
						fi_fprintf(fph, ",%f", (double)d.mMaxOutputValue / ONE_BTC);					// Maximum output value on this day
						fi_fprintf(fph, ",%d", d.mTotalOutputScriptLength);
						fi_fprintf(fph, ",%f", (double)d.mTotalOutputScriptLength / (double)d.mOutputCount);


						fi_fprintf(fph, ",%d", d.mMaxInputAge); //  oldest input

						fi_fprintf(fph, ",%d", d.mZombieInputCount); // number of inputs which were over 3 years old when spent
						fi_fprintf(fph, ",%f", d.mZombieInputValue); // total value of inputs which were over 3 years old when spent
						fi_fprintf(fph, ",%f", d.mZombieScore); // total value of inputs which were over 3 years old when spent

						fi_fprintf(fph, ",%d", d.mUTXOCount); // number of inputs which were over 3 years old when spent
						fi_fprintf(fph, ",%f", d.mUTXOValue); // total value of inputs which were over 3 years old when spent

						fi_fprintf(fph, ",%d", d.mEarlyCount); // number of inputs which were over 3 years old when spent
						fi_fprintf(fph, ",%f", d.mEarlyValue); // total value of inputs which were over 3 years old when spent


						for (uint32_t i = 0; i < AR_LAST; i++)
						{
							AgeStat &a = d.mAgeStats[i];
							fi_fprintf(fph, ",%d", a.mCount);
						}

						for (uint32_t i = 0; i < AR_LAST; i++)
						{
							AgeStat &a = d.mAgeStats[i];
							fi_fprintf(fph, ",%f", a.mValue);
						}


						fi_fprintf(fph, "\n");

					}

				}
				fi_fclose(fph);
			}
			else
			{
				logMessage("Failed to open file '%s' for write access.\n", reportFileName);
			}

			if (!mZombieInputs.empty())
			{
				logMessage("Encountered %s zombie inputs.\r\n", formatNumber(int32_t(mZombieInputs.size())));
				logMessage("Generating Zombie report.\r\n");
				FILE_INTERFACE *fph = fi_fopen("ZombieReport.csv", "wb", nullptr, 0, false);
				if (fph)
				{
					fi_fprintf(fph, "Date,LastDate,PublicKey,Age,Value,ZombieScore\r\n");
					for (size_t i = 0; i < mZombieInputs.size(); i++)
					{
						TransactionInput &input = mZombieInputs[i];
						Transaction t;
						bool ok = readTransaction(t, input.mTransactionFileOffset);
						assert(ok);
						if (ok)
						{
							assert(input.mTransactionIndex != 0xFFFFFFFF);
							if (input.mTransactionIndex != 0xFFFFFFFF)
							{
								assert(input.mTransactionIndex < t.mOutputs.size());
								if (input.mTransactionIndex < t.mOutputs.size())
								{
									TransactionOutput &output = t.mOutputs[input.mTransactionIndex];
									fi_fprintf(fph, "%s,", getDateString(input.mTimeStamp));
									fi_fprintf(fph, "%s,", getDateString(t.mTransactionTime));
									PublicKeyData &a = mAddresses[output.mIndex];
									fi_fprintf(fph, "%s,", getBitcoinAddressAscii(a.address));
									uint32_t days = getAgeInDays(t.mTransactionTime, input.mTimeStamp );
									fi_fprintf(fph, "%d,", days);
									double value = (double)output.mValue / ONE_BTC;
									fi_fprintf(fph, "%f,", value);
									double score = double(days*days)*value;
									fi_fprintf(fph, "%f,", score);
									fi_fprintf(fph, "\r\n");
								}
							}
						}
					}
					fi_fclose(fph);
				}
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

			if (days != mLastDay)
			{
				if (days > mLastDay)
				{
					logMessage("Accumulating Unspent Transaction Output Statistics for %s\r\n", getDateString(t.mTransactionTime));
					DailyStatistics &d = mDailyStatistics[mLastDay];
					d.mUTXOCount = uint32_t(mUTXOStats.size());
					// iterate through all unspent transaction outputs
					for (auto i = mUTXOStats.begin(); i != mUTXOStats.end(); ++i)
					{
						UTXOSTAT &stat = (*i).second;
						double value = (double)stat.mValue / ONE_BTC;

						if (isEarly(stat.mTimeStamp))
						{
							d.mEarlyCount++;
							d.mEarlyValue += value;
						}

						d.mUTXOValue += value;
						uint32_t age = getAgeInDays(stat.mTimeStamp, t.mTransactionTime);
						for (uint32_t i = 0; i < AR_LAST; i++)
						{
							if (age <= d.mAgeStats[i].mDays)
							{
								d.mAgeStats[i].mCount++;
								d.mAgeStats[i].mValue += value;
								break;
							}
						}
					}
					mLastDay = days;
				}
			}
			assert(days < MAXIMUM_DAYS);
			DailyStatistics &d = mDailyStatistics[days];
			if (t.mBlockNumber != d.mCurrentBlock)
			{
				d.mCurrentBlock = t.mBlockNumber;
				d.mBlockCount++;
				if (d.mTransactionBlockCount > d.mMaxTransactionBlockCount)
				{
					d.mMaxTransactionBlockCount = d.mTransactionBlockCount;
				}
				d.mTransactionBlockCount = 0;
			}
			d.mTransactionBlockCount++;
			d.mTransactionCount++;
			d.mTransactionSize += t.mTransactionSize;
			d.mInputCount += uint32_t(t.mInputs.size());
			d.mOutputCount += uint32_t(t.mOutputs.size());
			if (t.mInputs.size() > d.mMaxInputCount)
			{
				d.mMaxInputCount = uint32_t(t.mInputs.size());
			}
			if (t.mOutputs.size() > d.mMaxOutputCount)
			{
				d.mMaxInputCount = uint32_t(t.mOutputs.size());
			}
			if (t.mTransactionSize > d.mMaxTransactionSize)
			{
				d.mMaxTransactionSize = t.mTransactionSize;
			}
			// iterate through all of the inputs on this transaction and accumulate daily stats
			for (size_t i = 0; i < t.mInputs.size(); i++)
			{
				const TransactionInput &input = t.mInputs[i];

				if (input.mTransactionIndex != 0xFFFFFFFF )
				{
					UTXO utxo(input.mTransactionFileOffset, input.mTransactionIndex);
					UTXOStatMap::iterator found = mUTXOStats.find(utxo);
					if (found != mUTXOStats.end())
					{
						mUTXOStats.erase(found);
						if (input.mInputValue < DUST_VALUE)
						{
							d.mDustCount++;
						}
					}
					else
					{
						assert(0);
					}
				}


				d.mTotalInputScriptLength += input.mResponseScriptLength;
				d.mTotalInputValue += double(input.mInputValue) / ONE_BTC;
				if (input.mResponseScriptLength > d.mMaxInputScriptLength)
				{
					d.mMaxInputScriptLength = input.mResponseScriptLength;
				}
				if (input.mInputValue > d.mMaxInputValue)
				{
					d.mMaxInputValue = input.mInputValue;
				}
				uint32_t days = getAgeInDays(input.mTimeStamp, t.mTransactionTime);
				if (days > d.mMaxInputAge)
				{
					d.mMaxInputAge = days;
				}

				if (days > ZOMBIE_TIME)
				{
					TransactionInput ip = input;
					ip.mTimeStamp = t.mTransactionTime;
					mZombieInputs.push_back(ip);
					d.mZombieInputCount++;
					d.mZombieInputValue += double(input.mInputValue) / ONE_BTC;
				}

				d.mZombieScore += (double)(days*days)*(double(input.mInputValue) / ONE_BTC);
			}


			uint32_t count = uint32_t(t.mOutputs.size());
			switch (count)
			{
				case 0:
					assert(0); // should never happen!?
					break;
				case 1:
					{
						const TransactionOutput &to = t.mOutputs[0];
						d.mValueEntryTable.addValue(to.mValue);
					}
					break;
				case 2:
					{
						const TransactionOutput &t1 = t.mOutputs[0];
						const TransactionOutput &t2 = t.mOutputs[1];
						uint64_t v = t1.mValue;
						if (t2.mValue < v)
						{
							v = t2.mValue;
						}
						d.mValueEntryTable.addValue(v);
					}
					break;
				default:
					{
						uint64_t v = 0;
						for (uint32_t i = 0; i < count; i++)
						{
							const TransactionOutput &to = t.mOutputs[i];
							if (to.mValue > v)
							{
								v = to.mValue;
							}
						}
						d.mValueEntryTable.addValue(v);
					}
					break;
			}


			for (size_t i = 0; i < t.mOutputs.size(); i++)
			{
				const TransactionOutput &output = t.mOutputs[i];
				d.mTotalOutputScriptLength += output.mScriptLength;
				d.mTotalOutputValue += (double)(output.mValue) / ONE_BTC;
				if (output.mScriptLength > d.mMaxOutputScriptLength)
				{
					d.mMaxOutputScriptLength = output.mScriptLength;
				}
				if (output.mValue > d.mMaxOutputValue)
				{
					d.mMaxOutputValue = output.mValue;
				}

				UTXOSTAT stat(output.mValue, t.mTransactionTime);
				UTXO utxo(toffset, i);
				mUTXOStats[utxo] = stat;

				d.mKeyTypeCounts[output.mKeyType]++;
			}
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

		uint32_t					mLastDay;
		DailyStatistics				*mDailyStatistics;	// room to compute daily statistics
		UTXOMap						mUTXO;				// unspent transaction outputs...
		UTXOStatMap					mUTXOStats;			//

		TransactionInputVector		mZombieInputs;		// all zombie events
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
