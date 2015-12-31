#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <string>
#include <vector>
#include <unordered_set>

#include "BlockChain.h"			// The header for this system
#include "Base58.h"				// A helper interface to
#include "BitcoinAddress.h"
#include "RIPEMD160.h"
#include "SHA256.h"
#include "logging.h"

//
// Written by John W. Ratcliff : mailto: jratcliffscarab@gmail.com
//
// Website:  http://codesuppository.blogspot.com/
//
// Source contained in this project includes portions of source code from other open source projects; though that source may have
// been modified to be included here.  Original notices are left in where appropriate.
//
// Some of the hash and bignumber implementations are based on source code find in the 'cbitcoin' project; though it has been modified here to remove all memory allocations.
//
// http://cbitcoin.com/
//
// If you find this code snippet useful; you can tip me at this bitcoin address:
//
// BITCOIN TIP JAR: "1NY8SuaXfh8h5WHd4QnYwpgL1mNu9hHVBT"
//

#ifdef _MSC_VER // Disable the stupid ass absurd warning messages from Visual Studio telling you that using stdlib and stdio is 'not valid ANSI C'
#pragma warning(disable:4996)
#pragma warning(disable:4718)
#endif



// These defines set the limits this parser expects to ever encounter on the blockchain data stream.
// In a debug build there are asserts to make sure these limits are never exceeded.
// These limits work for the blockchain current as of July 1, 2013.
// The limits can be revised when and if necessary.
#define MAX_BLOCK_SIZE (1024*1024)*32	// never expect to have a block larger than 32mb
#define MAX_BLOCK_TRANSACTION 32768		// never expect more than 32768 transactions per block.
#define MAX_BLOCK_INPUTS 32768			// never expect more than 32768 total inputs
#define MAX_BLOCK_OUTPUTS 32768			// never expect more than 32768 total outputs

#define MAX_REASONABLE_SCRIPT_LENGTH (1024*32)	// would never expect any script to be more than 16k in size; that would be very unusual!
#define MAX_REASONABLE_INPUTS 32678				// really can't imagine any transaction ever having more than 32768 inputs
#define MAX_REASONABLE_OUTPUTS 32768			// really can't imagine any transaction ever having more than 32768 outputs

namespace BLOCK_CHAIN
{

	enum ScriptOpcodes
	{
		OP_0 = 0x00,
		OP_PUSHDATA1 = 0x4c,
		OP_PUSHDATA2 = 0x4d,
		OP_PUSHDATA4 = 0x4e,
		OP_1NEGATE = 0x4f,
		OP_RESERVED = 0x50,
		OP_1 = 0x51,
		OP_2 = 0x52,
		OP_3 = 0x53,
		OP_4 = 0x54,
		OP_5 = 0x55,
		OP_6 = 0x56,
		OP_7 = 0x57,
		OP_8 = 0x58,
		OP_9 = 0x59,
		OP_10 = 0x5a,
		OP_11 = 0x5b,
		OP_12 = 0x5c,
		OP_13 = 0x5d,
		OP_14 = 0x5e,
		OP_15 = 0x5f,
		OP_16 = 0x60,
		OP_NOP = 0x61,
		OP_VER = 0x62,
		OP_IF = 0x63,
		OP_NOTIF = 0x64,
		OP_VERIF = 0x65,
		OP_VERNOTIF = 0x66,
		OP_ELSE = 0x67,
		OP_ENDIF = 0x68,
		OP_VERIFY = 0x69,
		OP_RETURN = 0x6a,
		OP_TOALTSTACK = 0x6b,
		OP_FROMALTSTACK = 0x6c,
		OP_2DROP = 0x6d,
		OP_2DUP = 0x6e,
		OP_3DUP = 0x6f,
		OP_2OVER = 0x70,
		OP_2ROT = 0x71,
		OP_2SWAP = 0x72,
		OP_IFDUP = 0x73,
		OP_DEPTH = 0x74,
		OP_DROP = 0x75,
		OP_DUP = 0x76,
		OP_NIP = 0x77,
		OP_OVER = 0x78,
		OP_PICK = 0x79,
		OP_ROLL = 0x7a,
		OP_ROT = 0x7b,
		OP_SWAP = 0x7c,
		OP_TUCK = 0x7d,
		OP_CAT = 0x7e,	// Currently disabled
		OP_SUBSTR = 0x7f,	// Currently disabled
		OP_LEFT = 0x80,	// Currently disabled
		OP_RIGHT = 0x81,	// Currently disabled
		OP_SIZE = 0x82,	// Currently disabled
		OP_INVERT = 0x83,	// Currently disabled
		OP_AND = 0x84,	// Currently disabled
		OP_OR = 0x85,	// Currently disabled
		OP_XOR = 0x86,	// Currently disabled
		OP_EQUAL = 0x87,
		OP_EQUALVERIFY = 0x88,
		OP_RESERVED1 = 0x89,
		OP_RESERVED2 = 0x8a,
		OP_1ADD = 0x8b,
		OP_1SUB = 0x8c,
		OP_2MUL = 0x8d,	// Currently disabled
		OP_2DIV = 0x8e,	// Currently disabled
		OP_NEGATE = 0x8f,
		OP_ABS = 0x90,
		OP_NOT = 0x91,
		OP_0NOTEQUAL = 0x92,
		OP_ADD = 0x93,
		OP_SUB = 0x94,
		OP_MUL = 0x95,	// Currently disabled
		OP_DIV = 0x96,	// Currently disabled
		OP_MOD = 0x97,	// Currently disabled
		OP_LSHIFT = 0x98,	// Currently disabled
		OP_RSHIFT = 0x99,	// Currently disabled
		OP_BOOLAND = 0x9a,
		OP_BOOLOR = 0x9b,
		OP_NUMEQUAL = 0x9c,
		OP_NUMEQUALVERIFY = 0x9d,
		OP_NUMNOTEQUAL = 0x9e,
		OP_LESSTHAN = 0x9f,
		OP_GREATERTHAN = 0xa0,
		OP_LESSTHANOREQUAL = 0xa1,
		OP_GREATERTHANOREQUAL = 0xa2,
		OP_MIN = 0xa3,
		OP_MAX = 0xa4,
		OP_WITHIN = 0xa5,
		OP_RIPEMD160 = 0xa6,
		OP_SHA1 = 0xa7,
		OP_SHA256 = 0xa8,
		OP_HASH160 = 0xa9,
		OP_HASH256 = 0xaa,
		OP_CODESEPARATOR = 0xab,
		OP_CHECKSIG = 0xac,
		OP_CHECKSIGVERIFY = 0xad,
		OP_CHECKMULTISIG = 0xae,
		OP_CHECKMULTISIGVERIFY = 0xaf,
		OP_NOP1 = 0xb0,
		OP_NOP2 = 0xb1,
		OP_NOP3 = 0xb2,
		OP_NOP4 = 0xb3,
		OP_NOP5 = 0xb4,
		OP_NOP6 = 0xb5,
		OP_NOP7 = 0xb6,
		OP_NOP8 = 0xb7,
		OP_NOP9 = 0xb8,
		OP_NOP10 = 0xb9,
		OP_SMALLINTEGER = 0xfa,
		OP_PUBKEYS = 0xfb,
		OP_PUBKEYHASH = 0xfd,
		OP_PUBKEY = 0xfe,
		OP_INVALIDOPCODE = 0xff
	};

	// Some globals for error reporting.
	static uint32_t	gBlockTime = 0;
	static uint32_t gBlockIndex = 0;
	static uint32_t gTransactionIndex = 0;
	static uint32_t gOutputIndex = 0;
	static bool		gIsWarning = false;
	static bool		gReportTransactionHash = false;
	static const char *gDummyKeyAscii = "1BadkEyPaj5oW2Uw4nY5BkYbPRYyTyqs9A";
	static uint8_t gDummyKey[25];
	static const char *gZeroByteAscii = "1zeroBTYRExUcufrTkwg27LsAvrhehtCJ";
	static uint8_t gZeroByte[25];

	static bool inline isASCII(char c)
	{
		bool ret = false;

		if ((c >= 32 && c < 127) || c == 13)
		{
			ret = true;
		}

		return ret;
	}

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

	class BlockHeader : public Hash256
	{
	public:
		BlockHeader(void)
		{
			mFileIndex = 0;
			mFileOffset = 0;
			mBlockLength = 0;
		}

		BlockHeader(const Hash256 &h) : Hash256(h)
		{
			mFileIndex = 0;
			mFileOffset = 0;
			mBlockLength = 0;
		}

		// Here the == operator is used to see if the hash values match
		bool operator==(const BlockHeader &other) const
		{
			const Hash256 &a = *this;
			const Hash256 &b = other;
			return a == b;
		}

		uint32_t	mFileIndex;
		uint32_t	mFileOffset;
		uint32_t	mBlockLength;
		uint8_t		mPreviousBlockHash[32];
	};

	class FileLocation : public Hash256
	{
	public:
		FileLocation(void)
		{

		}
		FileLocation(const Hash256 &h, uint32_t fileIndex, uint32_t fileOffset, uint32_t fileLength, uint32_t transactionIndex) : Hash256(h)
		{
			mFileIndex = fileIndex;
			mFileOffset = fileOffset;
			mFileLength = fileLength;
			mTransactionIndex = transactionIndex;
		}

		// Here the == operator is used to see if the hash values match
		bool operator==(const BlockHeader &other) const
		{
			const Hash256 &a = *this;
			const Hash256 &b = other;
			return a == b;
		}


		uint32_t	mFileIndex;
		uint32_t	mFileOffset;
		uint32_t	mFileLength;
		uint32_t	mTransactionIndex;
	};

	struct BlockPrefix
	{
		uint32_t	mVersion;					// The block version number.
		uint8_t		mPreviousBlock[32];			// The 32 byte (256 bit) hash of the previous block in the blockchain
		uint8_t		mMerkleRoot[32];			// The 32 bye merkle root hash
		uint32_t	mTimeStamp;					// The block time stamp
		uint32_t	mBits;						// The block bits field.
		uint32_t	mNonce;						// The block random number 'nonce' field.
	};

#define MAGIC_ID 0xD9B4BEF9
#define ONE_BTC 100000000
#define ONE_MBTC (ONE_BTC/1000)

} // end of BLOCK_CHAIN namespace

// A template to compute the hash value for a BlockHeader
namespace std
{
	template <>
	struct hash<BLOCK_CHAIN::BlockHeader>
	{
		std::size_t operator()(const BLOCK_CHAIN::BlockHeader &k) const
		{
			return std::size_t(k.getHash());
		}
	};
	template <>
	struct hash<BLOCK_CHAIN::FileLocation>
	{
		std::size_t operator()(const BLOCK_CHAIN::FileLocation &k) const
		{
			return std::size_t(k.getHash());
		}
	};

}

namespace BLOCK_CHAIN
{

class BlockImpl : public BlockChain::Block
{
public:
	// Read one byte from the block-chain input stream.
	inline uint8_t readU8(void)
	{
		assert((mBlockRead + sizeof(uint8_t)) <= mBlockEnd);
		uint8_t ret = *(uint8_t *)mBlockRead;
		mBlockRead += sizeof(uint8_t);
		return ret;
	}

	// Read two bytes from the block-chain input stream.
	inline uint16_t readU16(void)
	{
		assert((mBlockRead + sizeof(uint16_t)) <= mBlockEnd);
		uint16_t ret = *(uint16_t *)mBlockRead;
		mBlockRead += sizeof(uint16_t);
		return ret;
	}

	// Read four bytes from the block-chain input stream.
	inline uint32_t readU32(void)
	{
		assert((mBlockRead + sizeof(uint32_t)) <= mBlockEnd);
		uint32_t ret = *(uint32_t *)mBlockRead;
		mBlockRead += sizeof(uint32_t);
		return ret;
	}

	// Read eight bytes from the block-chain input stream.
	inline uint64_t readU64(void)
	{
		assert((mBlockRead + sizeof(uint64_t)) <= mBlockEnd);
		uint64_t ret = *(uint64_t *)mBlockRead;
		mBlockRead += sizeof(uint64_t);
		return ret;
	}

	// Return the current stream pointer representing a 32byte hash and advance the read pointer accordingly
	inline const uint8_t *readHash(void)
	{
		const uint8_t *ret = mBlockRead;
		assert((mBlockRead + 32) <= mBlockEnd);
		mBlockRead += 32;
		return ret;
	}

	// reads a variable length integer.
	// See the documentation from here:  https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
	inline uint32_t readVariableLengthInteger(void)
	{
		uint32_t ret = 0;

		uint8_t v = readU8();
		if (v < 0xFD) // If it's less than 0xFD use this value as the unsigned integer
		{
			ret = (uint32_t)v;
		}
		else
		{
			uint16_t v = readU16();
			if (v < 0xFFFF)
			{
				ret = (uint32_t)v;
			}
			else
			{
				uint32_t v = readU32();
				if (v < 0xFFFFFFFF)
				{
					ret = (uint32_t)v;
				}
				else
				{
					assert(0); // never expect to actually encounter a 64bit integer in the block-chain stream; it's outside of any reasonable expected value
					uint64_t v = readU64();
					ret = (uint32_t)v;
				}
			}
		}
		return ret;
	}

	// Get the current read buffer address and advance the stream buffer by this length; used to get the address of input/output scripts
	inline const uint8_t * getReadBufferAdvance(uint32_t readLength)
	{
		const uint8_t *ret = mBlockRead;
		mBlockRead += readLength;
		assert(mBlockRead <= mBlockEnd);
		return ret;
	}


	// Read a transaction input
	bool readInput(BlockChain::BlockInput &input)
	{
		bool ret = true;

		input.transactionHash = readHash();	// read the transaction hash
		input.transactionIndex = readU32();	// read the transaction index
		input.responseScriptLength = readVariableLengthInteger();	// read the length of the script
		assert(input.responseScriptLength < MAX_REASONABLE_SCRIPT_LENGTH);

		if (input.responseScriptLength >= 8192)
		{
			logMessage("Block: %d : Unreasonably large input script length of %d bytes.\r\n", gBlockIndex, input.responseScriptLength);
		}

		if (input.responseScriptLength < MAX_REASONABLE_SCRIPT_LENGTH)
		{
			input.responseScript = input.responseScriptLength ? getReadBufferAdvance(input.responseScriptLength) : NULL;	// get the script buffer pointer; and advance the read location
			input.sequenceNumber = readU32();
		}
		else
		{
			logMessage("Block %d : Outrageous sized input script of %d bytes!  Shutting down.\r\n", gBlockIndex, input.responseScriptLength);
			exit(1);
		}
		return ret;
	}

	void getAsciiAddress(BlockChain::BlockOutput &o)
	{
		o.asciiAddress[0] = 0;
		char temp[256];

		switch (o.keyType)
		{
		case BlockChain::KT_MULTISIG:
			sprintf(o.asciiAddress, "MultiSig[%d]", o.signatureCount);
			break;
		case BlockChain::KT_STEALTH:
			strcat(o.asciiAddress, "*STEALTH*");
			break;
		case BlockChain::KT_SCRIPT_HASH:
			strcat(o.asciiAddress, "*SCRIPT_HASH*");
			break;
		default:
			break;
		}
		for (uint32_t i = 0; i < MAX_MULTISIG; i++)
		{
			if (o.publicKey[i])
			{
				if (i)
				{
					strcat(o.asciiAddress, ":");
				}
				bitcoinAddressToAscii(o.addresses[i].address, temp, 256);
				strcat(o.asciiAddress, temp);
			}
			else
			{
				break;
			}
		}
		// If this is a multi-sig address, *then* we need to generate a multisig address for it.
		if (o.keyType == BlockChain::KT_MULTISIG)
		{
			uint8_t hash[20];
			computeRIPEMD160(&o.addresses, 25 * MAX_MULTISIG, hash);
			bitcoinRIPEMD160ToAddress(hash, o.multisig.address);
		}
	}

	const char * getKeyType(BlockChain::KeyType k)
	{
		const char *ret = "UNKNOWN";
		switch (k)
		{
		case BlockChain::KT_RIPEMD160:
			ret = "RIPEMD160";
			break;
		case BlockChain::KT_UNCOMPRESSED_PUBLIC_KEY:
			ret = "UNCOMPRESSED_PUBLIC_KEY";
			break;
		case BlockChain::KT_COMPRESSED_PUBLIC_KEY:
			ret = "COMPRESSED_PUBLIC_KEY";
			break;
		case BlockChain::KT_TRUNCATED_COMPRESSED_KEY:
			ret = "TRUNCATED_COMPRESSED_KEY";
			break;
		case BlockChain::KT_MULTISIG:
			ret = "MULTISIG";
			break;
		case BlockChain::KT_STEALTH:
			ret = "STEALTH";
			break;
		case BlockChain::KT_ZERO_LENGTH:
			ret = "ZERO_LENGTH";
			break;
		case BlockChain::KT_SCRIPT_HASH:
			ret = "SCRIPT_HASH";
			break;
		default:
			break;
		}
		return ret;
	}

	// Read an output block
	bool readOutput(BlockChain::BlockOutput &output)
	{
		bool ret = true;

		new (&output) BlockChain::BlockOutput;

		output.value = readU64();	// Read the value of the transaction
		blockReward += output.value;
		output.challengeScriptLength = readVariableLengthInteger();
		assert(output.challengeScriptLength < MAX_REASONABLE_SCRIPT_LENGTH);

		if (output.challengeScriptLength >= 8192)
		{
			logMessage("Block %d : Unreasonably large output script length of %d bytes.\r\n", gBlockIndex, output.challengeScriptLength);
		}
		else if (output.challengeScriptLength > MAX_REASONABLE_SCRIPT_LENGTH)
		{
			logMessage("Block %d : output script too long %d bytes!\r\n", gBlockIndex, output.challengeScriptLength);
			exit(1);
		}

		output.challengeScript = output.challengeScriptLength ? getReadBufferAdvance(output.challengeScriptLength) : NULL; // get the script buffer pointer and advance the read location

		if (output.challengeScript)
		{
			uint8_t lastInstruction = output.challengeScript[output.challengeScriptLength - 1];
			if (output.challengeScriptLength == 67 && output.challengeScript[0] == 65 && output.challengeScript[66] == OP_CHECKSIG)
			{
				output.publicKey[0] = output.challengeScript + 1;
				output.keyType = BlockChain::KT_UNCOMPRESSED_PUBLIC_KEY;
			}
			if (output.challengeScriptLength == 40 && output.challengeScript[0] == OP_RETURN)
			{
				output.publicKey[0] = &output.challengeScript[1];
				output.keyType = BlockChain::KT_STEALTH;
			}
			else if (output.challengeScriptLength == 66 && output.challengeScript[65] == OP_CHECKSIG)
			{
				output.publicKey[0] = output.challengeScript;
				output.keyType = BlockChain::KT_UNCOMPRESSED_PUBLIC_KEY;
			}
			else if (output.challengeScriptLength == 35 && output.challengeScript[34] == OP_CHECKSIG)
			{
				output.publicKey[0] = &output.challengeScript[1];
				output.keyType = BlockChain::KT_COMPRESSED_PUBLIC_KEY;
			}
			else if (output.challengeScriptLength == 33 && output.challengeScript[0] == 0x20)
			{
				output.publicKey[0] = &output.challengeScript[1];
				output.keyType = BlockChain::KT_TRUNCATED_COMPRESSED_KEY;
			}
			else if (output.challengeScriptLength == 23 &&
				output.challengeScript[0] == OP_HASH160 &&
				output.challengeScript[1] == 20 &&
				output.challengeScript[22] == OP_EQUAL)
			{
				output.publicKey[0] = output.challengeScript + 2;
				output.keyType = BlockChain::KT_SCRIPT_HASH;
			}
			else if (output.challengeScriptLength >= 25 &&
				output.challengeScript[0] == OP_DUP &&
				output.challengeScript[1] == OP_HASH160 &&
				output.challengeScript[2] == 20)
			{
				output.publicKey[0] = output.challengeScript + 3;
				output.keyType = BlockChain::KT_RIPEMD160;
			}
			else if (output.challengeScriptLength == 5 &&
				output.challengeScript[0] == OP_DUP &&
				output.challengeScript[1] == OP_HASH160 &&
				output.challengeScript[2] == OP_0 &&
				output.challengeScript[3] == OP_EQUALVERIFY &&
				output.challengeScript[4] == OP_CHECKSIG)
			{
				logMessage("WARNING: Unusual but expected output script. Block %s : Transaction: %s : OutputIndex: %s\r\n", formatNumber(gBlockIndex), formatNumber(gTransactionIndex), formatNumber(gOutputIndex));
				gIsWarning = true;
			}
			else if (lastInstruction == OP_CHECKMULTISIG && output.challengeScriptLength > 25) // looks to be a multi-sig
			{
				const uint8_t *scanBegin = output.challengeScript;
				const uint8_t *scanEnd = &output.challengeScript[output.challengeScriptLength - 2];
				bool expectedPrefix = false;
				bool expectedPostfix = false;
				switch (*scanBegin)
				{
				case OP_0:
				case OP_1:
				case OP_2:
				case OP_3:
				case OP_4:
				case OP_5:
					expectedPrefix = true;
					break;
				default:
					//						assert(0); // unexpected
					break;
				}
				switch (*scanEnd)
				{
				case OP_1:
				case OP_2:
				case OP_3:
				case OP_4:
				case OP_5:
					expectedPostfix = true;
					break;
				default:
					//						assert(0); // unexpected
					break;
				}
				if (expectedPrefix && expectedPostfix)
				{
					scanBegin++;
					uint32_t keyIndex = 0;
					while (keyIndex < 5 && scanBegin < scanEnd)
					{
						if (*scanBegin == 0x21)
						{
							output.keyType = BlockChain::KT_MULTISIG;
							scanBegin++;
							output.publicKey[keyIndex] = scanBegin;
							scanBegin += 0x21;
							uint32_t bitMask = 1 << keyIndex;
							output.multiSigFormat |= bitMask; // turn this bit on if it is in compressed format
							keyIndex++;
						}
						else if (*scanBegin == 0x41)
						{
							output.keyType = BlockChain::KT_MULTISIG;
							scanBegin++;
							output.publicKey[keyIndex] = scanBegin;
							scanBegin += 0x41;
							keyIndex++;
						}
						else
						{
							break; //
						}
					}
				}
				if (output.publicKey[0] == NULL)
				{
					logMessage("****MULTI_SIG WARNING: Unable to decipher multi-sig output. Block %s : Transaction: %s : OutputIndex: %s\r\n", formatNumber(gBlockIndex), formatNumber(gTransactionIndex), formatNumber(gOutputIndex));
					gIsWarning = true;
				}
			}
			else
			{
				// Ok..we are going to scan for this pattern.. OP_DUP, OP_HASH160, 0x14 then exactly 20 bytes after 0x88,0xAC
				// 25...
				if (output.challengeScriptLength > 25)
				{
					uint32_t endIndex = output.challengeScriptLength - 25;
					for (uint32_t i = 0; i < endIndex; i++)
					{
						const uint8_t *scan = &output.challengeScript[i];
						if (scan[0] == OP_DUP &&
							scan[1] == OP_HASH160 &&
							scan[2] == 20 &&
							scan[23] == OP_EQUALVERIFY &&
							scan[24] == OP_CHECKSIG)
						{
							output.publicKey[0] = &scan[3];
							output.keyType = BlockChain::KT_RIPEMD160;
							logMessage("WARNING: Unusual output script. Block %s : Transaction: %s : OutputIndex: %s\r\n", formatNumber(gBlockIndex), formatNumber(gTransactionIndex), formatNumber(gOutputIndex));
							gIsWarning = true;
							break;
						}
					}
				}
			}
			if (output.publicKey[0] == NULL)
			{
				logMessage("==========================================\r\n");
				logMessage("FAILED TO LOCATE PUBLIC KEY\r\n");
				logMessage("ChallengeScriptLength: %d bytes long\r\n", output.challengeScriptLength);
				for (uint32_t i = 0; i < output.challengeScriptLength; i++)
				{
					logMessage("%02x ", output.challengeScript[i]);
					if (((i + 16) & 15) == 0)
					{
						logMessage("\r\n");
					}
				}
				logMessage("\r\n");
				logMessage("==========================================\r\n");
				logMessage("\r\n");
			}
		}
		else
		{
			logMessage("Block %d : has a zero byte length output script?\r\n", gBlockIndex);
			gReportTransactionHash = true;
		}

		if (!output.publicKey[0])
		{
			if (output.challengeScriptLength == 0)
			{
				output.publicKey[0] = &gZeroByte[1];
			}
			else
			{
				output.publicKey[0] = &gDummyKey[1];
			}
			output.keyType = BlockChain::KT_RIPEMD160;
			logMessage("WARNING: Failed to decode public key in output script. Block %s : Transaction: %s : OutputIndex: %s scriptLength: %s\r\n", formatNumber(gBlockIndex), formatNumber(gTransactionIndex), formatNumber(gOutputIndex), formatNumber(output.challengeScriptLength));
			gReportTransactionHash = true;
			gIsWarning = true;
		}


		switch (output.keyType)
		{
		case BlockChain::KT_RIPEMD160:
			bitcoinRIPEMD160ToAddress(output.publicKey[0], output.addresses[0].address);
			break;
		case BlockChain::KT_SCRIPT_HASH:
			bitcoinRIPEMD160ToScriptAddress(output.publicKey[0], output.addresses[0].address);
			break;
		case BlockChain::KT_STEALTH:
			bitcoinRIPEMD160ToAddress(output.publicKey[0], output.addresses[0].address);
			break;
		case BlockChain::KT_UNCOMPRESSED_PUBLIC_KEY:
		{
			bitcoinPublicKeyToAddress(output.publicKey[0], output.addresses[0].address);
		}
		break;
		case BlockChain::KT_COMPRESSED_PUBLIC_KEY:
		{
			bitcoinCompressedPublicKeyToAddress(output.publicKey[0], output.addresses[0].address);
		}
		break;
		case BlockChain::KT_TRUNCATED_COMPRESSED_KEY:
		{
			uint8_t key[33];
			key[0] = 0x2;
			memcpy(&key, output.publicKey[0], 32);
			bitcoinCompressedPublicKeyToAddress(key, output.addresses[0].address);
		}
		break;
		case BlockChain::KT_MULTISIG:
		{
			for (uint32_t i = 0; i < MAX_MULTISIG; i++)
			{
				const uint8_t *key = output.publicKey[i];
				if (key == NULL)
					break;
				uint32_t mask = 1 << i;
				if (output.multiSigFormat & mask)
				{
					bitcoinCompressedPublicKeyToAddress(output.publicKey[i], output.addresses[i].address);
				}
				else
				{
					bitcoinPublicKeyToAddress(output.publicKey[i], output.addresses[i].address);
				}
			}
		}
		break;
		default:
			break;
		}
		output.keyTypeName = getKeyType(output.keyType);
		getAsciiAddress(output);

		//		if ( output.keyType == BlockChain::KT_SCRIPT_HASH )
		//		{
		//			logMessage("ScriptHash: %s\r\n", output.asciiAddress );
		//		}

		if (gReportTransactionHash)
		{
			gIsWarning = true;
		}
		return ret;
	}

	// Read a single transaction
	bool readTransaction(BlockChain::BlockTransaction &transaction,
		uint32_t &transactionIndex,
		uint32_t tindex)
	{
		bool ret = false;

		const uint8_t *transactionBegin = mBlockRead;

		transaction.transactionVersionNumber = readU32(); // read the transaction version number; always expect it to be 1

		if (transaction.transactionVersionNumber == 1 || transaction.transactionVersionNumber == 2)
		{
		}
		else
		{
			gIsWarning = true;
			logMessage("Encountered unusual and unexpected transaction version number of [%d] for transaction #%d\r\n", transaction.transactionVersionNumber, tindex);
		}

		transaction.inputCount = readVariableLengthInteger();
		assert(transaction.inputCount < MAX_REASONABLE_INPUTS);
		if (transaction.inputCount >= MAX_REASONABLE_INPUTS)
		{
			logMessage("Invalid number of inputs found! %d\r\n", transaction.inputCount);
			exit(1);
		}
		transaction.inputs = &mInputs[totalInputCount];
		totalInputCount += transaction.inputCount;
		assert(totalInputCount < MAX_BLOCK_INPUTS);
		if (totalInputCount >= MAX_BLOCK_INPUTS)
		{
			logMessage("Invalid number of block inputs: %d\r\n", totalInputCount);
			exit(1);
		}
		if (totalInputCount < MAX_BLOCK_INPUTS)
		{
			for (uint32_t i = 0; i < transaction.inputCount; i++)
			{
				BlockChain::BlockInput &input = transaction.inputs[i];
				ret = readInput(input);	// read the input
				if (!ret)
				{
					logMessage("Failed to read input!\r\n");
					exit(1);
					//					break;
				}
			}
		}
		if (ret)
		{
			transaction.outputCount = readVariableLengthInteger();
			assert(transaction.outputCount < MAX_REASONABLE_OUTPUTS);
			if (transaction.outputCount > MAX_REASONABLE_OUTPUTS)
			{
				logMessage("Exceeded maximum reasonable outputs.\r\n");
				exit(1);
			}
			transaction.outputs = &mOutputs[totalOutputCount];
			totalOutputCount += transaction.outputCount;
			assert(totalOutputCount < MAX_BLOCK_OUTPUTS);
			if (totalOutputCount >= MAX_BLOCK_OUTPUTS)
			{
				logMessage("Invalid number of block outputs. %d\r\n", totalOutputCount);
				exit(1);
			}
			if (totalOutputCount < MAX_BLOCK_OUTPUTS)
			{
				for (uint32_t i = 0; i < transaction.outputCount; i++)
				{
					gOutputIndex = i;
					BlockChain::BlockOutput &output = transaction.outputs[i];
					ret = readOutput(output);
					if (!ret)
					{
						logMessage("Failed to read output.\r\n");
						exit(1);
						//						break;
					}
				}

				transaction.lockTime = readU32();

				{
					transaction.transactionLength = (uint32_t)(mBlockRead - transactionBegin);
					transaction.fileIndex = fileIndex;
					transaction.fileOffset = fileOffset + (uint32_t)(transactionBegin - mBlockData);
					transaction.transactionIndex = transactionIndex;
					transactionIndex++;
					computeSHA256(transactionBegin, transaction.transactionLength, transaction.transactionHash);
					computeSHA256(transaction.transactionHash, 32, transaction.transactionHash);

					if (gReportTransactionHash)
					{
						logMessage("TRANSACTION HASH:");
						printReverseHash(transaction.transactionHash);
						logMessage("\r\n");
						gReportTransactionHash = false;
					}

				}

			}
		}
		return ret;
	}

	// @see this link for detailed documentation:
	//
	// http://james.lab6.com/2012/01/12/bitcoin-285-bytes-that-changed-the-world/
	//
	// read a single block from the block chain into memory
	// Here is how a block is read.
	//
	// Step #1 : We read the block format version
	// Step #2 : We read the hash of the previous block
	// Step #3 : We read the merkle root hash
	// Step #4 : We read the block time stamp
	// Step #5 : We read a 'bits' field; internal use defined by the bitcoin software
	// Step #6 : We read the 'nonce' value; a randum number generated during the mining process.
	// Step #7 : We read the transaction count
	// Step #8 : For/Each Transaction
	//          : (a) We read the transaction version number.
	//          : (b) We read the number of inputs.
	//Step #8a : For/Each input
	//			: (a) Read the hash of the input transaction
	//			: (b) Read the input transaction index
	//			: (c) Read the response script length
	//			: (d) Read the response script data; parsed using the bitcoin scripting system; a little virtual machine.
	//			: Read the sequence number.
	//			: Read the number of outputs
	//Step #8b : For/Each Output
	//			: (a) Read the value of the output in BTC fixed decimal; see docs.
	//			: (b) Read the length of the challenge script.
	//			: (c) Read the challenge script
	//Step #9 Read the LockTime; a value currently always hard-coded to zero
	bool processBlockData(const void *blockData, uint32_t blockLength, uint32_t &transactionIndex)
	{
		bool ret = true;
		mBlockData = (const uint8_t *)blockData;
		mBlockRead = mBlockData;	// Set the block-read scan pointer.
		mBlockEnd = &mBlockData[blockLength]; // Mark the end of block pointer
		blockFormatVersion = readU32();	// Read the format version
		previousBlockHash = readHash();  // get the address of the hash
		merkleRoot = readHash();	// Get the address of the merkle root hash
		gBlockTime = timeStamp = readU32();	// Get the timestamp
		bits = readU32();	// Get the bits field
		nonce = readU32();	// Get the 'nonce' random number.
		transactionCount = readVariableLengthInteger();	// Read the number of transactions
		assert(transactionCount < MAX_BLOCK_TRANSACTION);
		if (transactionCount >= MAX_BLOCK_TRANSACTION)
		{
			logMessage("Too many transactions in the block: %d\r\n", transactionCount);
			exit(1);
		}
		if (transactionCount < MAX_BLOCK_TRANSACTION)
		{
			transactions = mTransactions;	// Assign the transactions buffer pointer
			for (uint32_t i = 0; i < transactionCount; i++)
			{
				gTransactionIndex = i;
				BlockChain::BlockTransaction &b = transactions[i];
				if (!readTransaction(b, transactionIndex, i))	// Read the transaction; if it failed; then abort processing the block chain
				{
					ret = false;
					break;
				}
			}
		}

		return ret;
	}
	const BlockChain::BlockTransaction *processTransactionData(const void *transactionData, uint32_t transactionLength)
	{
		uint32_t transactionIndex = 0;
		BlockChain::BlockTransaction *ret = &mTransactions[0];
		mBlockData = (const uint8_t *)transactionData;
		mBlockRead = mBlockData;	// Set the block-read scan pointer.
		mBlockEnd = &mBlockData[transactionLength]; // Mark the end of block pointer

		if (!readTransaction(*ret, transactionIndex, 0))	// Read the transaction; if it failed; then abort processing the block chain
		{
			ret = NULL;
			logMessage("Failed to process transaction data!\r\n");
			exit(1);
		}
		return ret;
	}




	const uint8_t					*mBlockRead;				// The current read buffer address in the block
	const uint8_t					*mBlockEnd;					// The EOF marker for the block
	const uint8_t					*mBlockData;
	BlockChain::BlockTransaction	mTransactions[MAX_BLOCK_TRANSACTION];	// Holds the array of transactions
	BlockChain::BlockInput			mInputs[MAX_BLOCK_INPUTS];	// The input arrays
	BlockChain::BlockOutput			mOutputs[MAX_BLOCK_OUTPUTS]; // The output arrays


};

class BlockChainImpl : public BlockChain
{
public:

	typedef std::vector< FILE * > FILEVector;
	typedef std::vector< BlockHeader *> BlockHeaderVector;
	typedef std::unordered_set< BlockHeader > BlockHeaderSet;
	typedef std::unordered_set< FileLocation > FileLocationSet;

	BlockChainImpl(const char *rootDir,uint32_t maxBlocks)
	{
		mTotalTransactionCount = 0;
		mTotalInputCount = 0;
		mTotalOutputCount = 0;
		mBlockCount = 0;
		mTransactionCount = 0;
		mSearchForText = 0;
		mTextReport = NULL;
		mMaxBlocks = maxBlocks;
		mRootDir = std::string(rootDir);
		mScanCount = 0;
		mReadCount = 0;
		mBlockIndex = 0;
		mFileLength = 0;
		mCurrentBlockData = mBlockDataBuffer;	// scratch buffer to read up to 3 blocks
		mBlockChainHeaders = nullptr;
		bitcoinAsciiToAddress(gDummyKeyAscii, gDummyKey);
		bitcoinAsciiToAddress(gZeroByteAscii, gZeroByte);
		openBlock();
	}

	virtual ~BlockChainImpl(void)
	{
		for (FILEVector::iterator i = mBlockDataFiles.begin(); i!=mBlockDataFiles.end(); ++i)
		{
			FILE *f = (*i);
			fclose(f);
		}
		if (mTextReport)
		{
			fclose(mTextReport);
		}
		delete[]mBlockChainHeaders;
	}

	// Initial scan of the blockchain to build the hash table of valid blocks; skipping orphan blocks
	// Will return 'true' if the scan is complete.  'lastBlockRead' is assigned the number of blocks we have processed so far.
	virtual bool scanBlockChain(uint32_t &lastBlockRead)
	{
		bool ret = true; // scan is complete by default...

		if (readBlockHeader() && mScanCount < mMaxBlocks)
		{
			lastBlockRead = mScanCount;
			mScanCount++;
			ret = false;
		}
		return ret; // scan is complete
	}

	// Initial scan of the blockchain to build the hash table of blocks in forward order.
	// Contrary to what you might think, or expect, the blocks in the file are not in the order of 
	// 0,1,2,3,4 etc.  The reason for this is that sometimes, while the client is connected to the network, orphan blocks get written
	// out.  So, the only way to know the correct blockchain is to sequentally scan to the last block found.  For each block we compute it's
	// hash and store it into a hash-table.  Then, to build the correct version of the blockchain we have to walk the linked-list backwards from
	// the last block to the first; leaving orphans out of it.
	bool readBlockHeader(void)
	{
		bool ret = false;

		// Make sure we have an open file to access
		if (mBlockIndex < mBlockDataFiles.size())
		{
			// Get the file pointer for the current blk?????.dat file we are scanning
			FILE *fph = mBlockDataFiles[mBlockIndex];
			uint32_t magicID = 0;
			uint32_t lastBlockRead = (uint32_t)ftell(fph);
			// Attempt to read the 'magicid' which we expect to see at the start of each block
			size_t r = fread(&magicID, sizeof(magicID), 1, fph);	// Attempt to read the magic id for the next block
			if (r == 0)
			{
				if (openBlock()) // Attempt to open the next block, if successful, look for the magicID in it.
				{
					fph = mBlockDataFiles[mBlockIndex];
					r = fread(&magicID, sizeof(magicID), 1, fph); // if we opened up a new file; read the magic id from it's first block.
					lastBlockRead = ftell(fph);
				}
			}
			// If after reading the previous block, we did not encounter a block header, we need to scan for the next block header..
			if (r == 1 && magicID != MAGIC_ID)
			{
				fseek(fph, lastBlockRead, SEEK_SET);
				logMessage("Warning: Missing block-header; scanning for next one.\r\n");
				uint8_t *temp = (uint8_t *)::malloc(MAX_BLOCK_SIZE);
				memset(temp, 0, MAX_BLOCK_SIZE);
				uint32_t c = (uint32_t)fread(temp, 1, MAX_BLOCK_SIZE, fph);
				bool found = false;
				if (c > 0)
				{
					for (uint32_t i = 0; i < c; i++)
					{
						const uint32_t *check = (const uint32_t *)&temp[i];
						if (*check == MAGIC_ID)
						{
							logMessage("Found the next block header after skipping: %s bytes forward in the file.\r\n", formatNumber(i));
							lastBlockRead += i; // advance to this location.
							found = true;
							break;
						}
					}
				}
				::free(temp);
				if (found)
				{
					fseek(fph, lastBlockRead, SEEK_SET);
					r = fread(&magicID, sizeof(magicID), 1, fph); // if we opened up a new file; read the magic id from it's first block.
					assert(magicID == MAGIC_ID);
				}

				if (found) // if we found it before the EOF, we are cool, otherwise, we need to advance to the next file.
				{
				}
				else
				{
					if (openBlock())
					{
						fph = mBlockDataFiles[mBlockIndex];
						r = fread(&magicID, sizeof(magicID), 1, fph); // if we opened up a new file; read the magic id from it's first block.
						if (r == 1)
						{
							if (magicID != MAGIC_ID)
							{
								logMessage("Advanced to the next data file; but it does not start with a valid block.  Aborting reading the block-chain.\r\n");
								r = 0;
							}
						}
					}
					else
					{
						r = 0; // done
					}
				}
			}
			if (r == 1)	// Ok, this is a valid block, let's continue
			{
				BlockHeader header;
				BlockPrefix prefix;
				header.mFileIndex = mBlockIndex;
				r = fread(&header.mBlockLength, sizeof(header.mBlockLength), 1, fph); // read the length of the block
				header.mFileOffset = (uint32_t)ftell(fph);
				if (r == 1)
				{
					assert(header.mBlockLength < MAX_BLOCK_SIZE); // make sure the block length does not exceed our maximum expected ever possible block size
					if (header.mBlockLength < MAX_BLOCK_SIZE)
					{
						r = fread(&prefix, sizeof(prefix), 1, fph); // read the rest of the block (less the 8 byte header we have already consumed)
						if (r == 1)
						{
							Hash256 *blockHash = static_cast<Hash256 *>(&header);
							memcpy(header.mPreviousBlockHash, prefix.mPreviousBlock, 32);
							computeSHA256((uint8_t *)&prefix, sizeof(prefix), (uint8_t *)blockHash);
							computeSHA256((uint8_t *)blockHash, 32, (uint8_t *)blockHash);
							uint32_t currentFileOffset = ftell(fph); // get the current file offset.
							uint32_t advance = header.mBlockLength - sizeof(BlockPrefix);
							currentFileOffset += advance;
							fseek(fph, currentFileOffset, SEEK_SET); // skip past the block to get to the next header.
							mLastBlockHeader = header;
							mBlockHeaderSet.insert(header);
							ret = true;
						}
					}
				}
			}
		}

		return ret;
	}

	// Opens the FILE associated with the next section of blocks (blk?????.dat) sequence
	bool openBlock(void)
	{
		bool ret = false;

		mBlockIndex = uint32_t(mBlockDataFiles.size()); // this is which one we are trying to open...
		char scratch[512];
#ifdef _MSC_VER
		sprintf(scratch, "%s\\blk%05d.dat", mRootDir.c_str(), mBlockIndex);	// get the filename
#else
		sprintf(scratch, "%s/blk%05d.dat", mRootDir.c_str(), mBlockIndex);	// get the filename
#endif
		FILE *fph = fopen(scratch, "rb");
		if (fph)
		{
			fseek(fph, 0L, SEEK_END);
			mFileLength = uint32_t(ftell(fph));
			fseek(fph, 0L, SEEK_SET);
			mBlockDataFiles.push_back(fph);
			logMessage("Opened blockchain file '%s' for read access.\r\n", scratch);
			ret = true;
		}
		else
		{
			logMessage("Failed to open blockchain file '%s' for read access.\r\n", scratch);
			ret = false;
		}
		return ret;
	}

	virtual void release(void) 	// This method releases the block chain interface.
	{
		delete this;
	}

	// Once scanning is completed, we build the blockchain by traversing, as a linked list, the last block to every previous block.
	// This will allow it to successfully skip orphaned blocks.  Return value is the last valid block number encountered.
	virtual uint32_t buildBlockChain(void)
	{
		uint32_t blockCount = 0;
		if (mScanCount)
		{

			uint32_t btotal = uint32_t(mBlockHeaderSet.size());
			logMessage("Found %s block headers total.\r\n", formatNumber(btotal));

			logMessage("Building complete block-chain.\r\n");
			// need to count the total number of blocks...

			BlockHeaderSet::iterator found = mBlockHeaderSet.find(mLastBlockHeader);
			while (found != mBlockHeaderSet.end() )
			{
				blockCount++;
				BlockHeader temp((*found).mPreviousBlockHash);
				found = mBlockHeaderSet.find(temp);
			}
			logMessage("Found %s blocks and skipped %s orphan blocks.\r\n", formatNumber(blockCount), formatNumber(btotal - blockCount));

			mBlockChainHeaders = new BlockHeader[blockCount];
			// Now that we know how many blocks are available, we add them to the list
			logMessage("Gathering %s block headers.\r\n", formatNumber(blockCount));
			uint32_t index = blockCount - 1;
			found = mBlockHeaderSet.find(mLastBlockHeader);
			while (found != mBlockHeaderSet.end())
			{
				mBlockChainHeaders[index] = (*found);
				index--;
				BlockHeader temp((*found).mPreviousBlockHash);
				found = mBlockHeaderSet.find(temp);
			}
			mBlockCount = blockCount;

			mScanCount = 0;
		}
		return blockCount;
	}

	virtual const Block *readBlock(uint32_t blockIndex)
	{
		Block *ret = nullptr;
		if (readBlock(mSingleReadBlock, blockIndex))
		{
			ret = &mSingleReadBlock;
		}
		return ret;
	}

	virtual bool readBlock(BlockImpl &block, uint32_t blockIndex)
	{
		bool ret = false;

		if (blockIndex >= mBlockCount) return false;
		BlockHeader &header = mBlockChainHeaders[blockIndex];
		FILE *fph = mBlockDataFiles[header.mFileIndex];
		if (fph)
		{
			block.blockIndex = blockIndex;
			block.warning = false;
			fseek(fph, header.mFileOffset, SEEK_SET);
			gBlockIndex = blockIndex;
			block.blockLength = header.mBlockLength;
			block.blockReward = 0;
			block.totalInputCount = 0;
			block.totalOutputCount = 0;
			block.fileIndex = header.mFileIndex;
			block.fileOffset = header.mFileOffset;
			block.blockLength = header.mBlockLength;

			if (blockIndex < (mBlockCount - 2))
			{
				BlockHeader *nextNext = &mBlockChainHeaders[blockIndex + 2];
				block.nextBlockHash = nextNext->mPreviousBlockHash;
			}

			uint8_t *blockData = mBlockDataBuffer;
			size_t r = fread(blockData, block.blockLength, 1, fph); // read the rest of the block (less the 8 byte header we have already consumed)

			if (r == 1)
			{
				computeSHA256(blockData, 4 + 32 + 32 + 4 + 4 + 4, block.computedBlockHash);
				computeSHA256(block.computedBlockHash, 32, block.computedBlockHash);
				ret = block.processBlockData(blockData, block.blockLength, mTransactionCount);


				if (mSearchForText) // if we are searching for ASCII text in the input stream...
				{
					uint32_t textCount = 0;
					const char *scan = (const char *)blockData;
					const char *end_scan = scan + (block.blockLength - mSearchForText);
					char *scratch = new char[MAX_BLOCK_SIZE];
					uint32_t lineCount = 0;
					uint32_t totalCount = 0;
					while (scan < end_scan)
					{
						uint32_t count = 0;
						//						const char *begin = scan;
						char *dest = scratch;
						while (isASCII(*scan) && scan < end_scan)
						{
							*dest++ = *scan++;
							count++;
						}
						if (count >= mSearchForText)
						{
							*dest = 0;
							if (textCount == 0)
							{
								if (mTextReport == 0)
								{
									mTextReport = fopen("AsciiTextReport.txt", "wb");
								}
								if (mTextReport)
								{
									fprintf(mTextReport, "==========================================\r\n");
									fprintf(mTextReport, "= ASCII TEXT REPORT for Block #%s on %s\r\n", formatNumber(blockIndex), getDateString(block.timeStamp));
									fprintf(mTextReport, "==========================================\r\n");
								}
							}
							textCount++;
							if (mTextReport)
							{
								fprintf(mTextReport, "%s", scratch);
								lineCount += count;
								totalCount += count;
								if (lineCount > 80)
								{
									fprintf(mTextReport, "\r\n");
									lineCount = 0;
								}
							}
						}
						scan++;
					}
					if (textCount && mTextReport)
					{
						fprintf(mTextReport, "\r\n");
						fprintf(mTextReport, "==========================================\r\n");
						if (totalCount >= 128)
						{
							fprintf(mTextReport, "Very Long Text: %d bytes\r\n", totalCount);
						}
						else if (totalCount >= 64)
						{
							fprintf(mTextReport, "Long Text: %d bytes\r\n", totalCount);
						}
						else
						{
							fprintf(mTextReport, "Short Text: %d bytes\r\n", totalCount);
						}
						fprintf(mTextReport, "\r\n");
						fflush(mTextReport);
					}
					delete[]scratch;
				}

				if (ret)
				{
					processTransactions(block);
				}
			}
			else
			{
				logMessage("Failed to read input block.  BlockChain corrupted.\r\n");
				exit(1);
			}
		}
		block.warning = gIsWarning;
		gIsWarning = false;
		return ret;
	}


	virtual void setSearchTextLength(uint32_t textLen)
	{
		mSearchForText = textLen;
	}

	virtual const BlockTransaction *processSingleTransaction(const void *transactionData,uint32_t transactionLength)
	{
		const BlockTransaction *ret = NULL;
		if ( transactionLength < MAX_BLOCK_SIZE )
		{
			mSingleTransactionBlock.blockIndex = 0;
			mSingleTransactionBlock.blockReward = 0;
			mSingleTransactionBlock.totalInputCount = 0;
			mSingleTransactionBlock.totalOutputCount = 0;
			mSingleTransactionBlock.fileIndex = 0;
			mSingleTransactionBlock.fileOffset =  0;
			ret = mSingleTransactionBlock.processTransactionData(transactionData,transactionLength);
		}
		return ret;

	}


	virtual const BlockTransaction *readSingleTransaction(const uint8_t *transactionHash)
	{
		const BlockTransaction *ret = NULL;

		Hash256 h(transactionHash);
		FileLocation key(h,0,0,0,0);
		FileLocationSet::iterator found = mTransactionSet.find(key);
		if ( found == mTransactionSet.end() )
		{
			logMessage("ERROR: Unable to locate this transaction hash:");
			printReverseHash(transactionHash);
			logMessage("\r\n");
			return NULL;
		}
		const FileLocation &f = *found;
		uint32_t fileIndex = f.mFileIndex;
		uint32_t fileOffset = f.mFileOffset;
		uint32_t transactionLength = f.mFileLength;

		if ( fileIndex < mBlockDataFiles.size() && mBlockDataFiles[fileIndex] && transactionLength < MAX_BLOCK_SIZE )
		{
			FILE *fph = mBlockDataFiles[fileIndex];
			uint32_t saveLocation = (uint32_t)ftell(fph);
			fseek(fph,fileOffset,SEEK_SET);
			uint32_t s = (uint32_t)ftell(fph);
			if ( s == fileOffset )
			{
				uint8_t *blockData = mTransactionBlockBuffer;
				size_t r = fread(blockData,transactionLength,1,fph);
				if ( r == 1 ) // if we successfully read in the entire transaction
				{
					ret = processSingleTransaction(blockData,transactionLength);
					if ( ret )
					{
						BlockTransaction *t = (BlockTransaction *)ret;
						t->transactionIndex = f.mTransactionIndex;
						t->fileIndex = fileIndex;
						t->fileOffset = fileOffset;
					}
				}
				else
				{
					assert(0);
				}
			}
			else
			{
				assert(0);
			}
			fseek(fph,saveLocation,SEEK_SET); // restore the file position back to it's previous location.
		}
		else
		{
			assert(0);
		}
		return ret;
	}


	// print the contents of this block
	virtual void printBlock(const Block *block) // prints the contents of the block to the console for debugging purposes
	{
		logMessage("==========================================================================================\r\n");
		logMessage("Block #%s\r\n", formatNumber(block->blockIndex) );

		logMessage("ComputedBlockHash: ");
		printReverseHash(block->computedBlockHash);
		logMessage("\r\n");

		if ( block->previousBlockHash )
		{
			logMessage("PreviousBlockHash:");
			printReverseHash(block->previousBlockHash);
			logMessage("\r\n");
		}
		if ( block->nextBlockHash )
		{
			logMessage("NextBlockHash:");
			printReverseHash(block->nextBlockHash);
			logMessage("\r\n");
		}


		logMessage("Merkle root: ");
		printReverseHash(block->merkleRoot);
		logMessage("\r\n");

		logMessage("Number of Transactions: %s\r\n", formatNumber(block->transactionCount) );
		logMessage("Timestamp : %s\r\n", getTimeString(block->timeStamp ) );
		logMessage("Bits: %d Hex: %08X\r\n", block->bits, block->bits );
		logMessage("Size: %0.10f KB or %s bytes.\r\n", (float)block->blockLength / 1024.0f, formatNumber(block->blockLength) );
		logMessage("Version: %d\r\n", block->blockFormatVersion );
		logMessage("Nonce: %u\r\n", block->nonce );
		logMessage("BlockReward: %f\r\n", (float)block->blockReward / ONE_BTC );

		logMessage("%s transactions\r\n", formatNumber(block->transactionCount) );
		for (uint32_t i=0; i<block->transactionCount; i++)
		{
			const BlockTransaction &t = block->transactions[i];
			logMessage("Transaction %s : %s inputs %s outputs. VersionNumber: %d\r\n", formatNumber(i), formatNumber(t.inputCount), formatNumber(t.outputCount), t.transactionVersionNumber );
			logMessage("TransactionHash: ");
			printReverseHash(t.transactionHash);
			logMessage("\r\n");
			for (uint32_t i=0; i<t.inputCount; i++)
			{
				const BlockInput &input = t.inputs[i];
				logMessage("    Input %s : ResponsScriptLength: %s TransactionIndex: %s : TransactionHash: ", formatNumber(i), formatNumber(input.responseScriptLength), formatNumber(input.transactionIndex) );

				printReverseHash(input.transactionHash);

				logMessage("\r\n");

				if ( input.transactionIndex != 0xFFFFFFFF )
				{
					const BlockTransaction *t = readSingleTransaction(input.transactionHash);
					if ( t == NULL )
					{
						logMessage("ERROR: TransactionIndex[%d] FAILED TO LOCATE TRANSACTION FOR HASH: ", input.transactionIndex );
						printReverseHash(input.transactionHash);
						logMessage("\r\n");
					}
					else
					{
						if ( input.transactionIndex < t->outputCount )
						{
							const BlockOutput &o = t->outputs[input.transactionIndex];
							if ( o.publicKey[0] )
							{
								logMessage("     Spending From Public Key: %s in the amount of: %0.4f\r\n", o.asciiAddress, (float)o.value / ONE_BTC );
							}
							else
							{
								logMessage("ERROR: No public key found for this previous output.\r\n");
							}
						}
						else
						{
							logMessage("ERROR: Invalid transaction index!\r\n");
						}
					}
				}
			}
			for (uint32_t i=0; i<t.outputCount; i++)
			{
				const BlockOutput &output = t.outputs[i];
				logMessage("    Output: %s : %f BTC : ChallengeScriptLength: %s\r\n", formatNumber(i), (float)output.value / ONE_BTC, formatNumber(output.challengeScriptLength) );
				if ( output.publicKey[0] )
				{
					logMessage("PublicKey: %s : %s\r\n", output.asciiAddress, output.keyTypeName );
				}
				else
				{
					logMessage("ERROR: Unable to derive a public key for this output!\r\n");
				}
			}
		}

		logMessage("==========================================================================================\r\n");
	}

	void processTransactions(Block &block)
	{
		mTotalTransactionCount+=block.transactionCount;

		for (uint32_t i=0; i<block.transactionCount; i++)
		{
			BlockTransaction &t = block.transactions[i];
			Hash256 hash(t.transactionHash);
			FileLocation f(hash,t.fileIndex,t.fileOffset,t.transactionLength,t.transactionIndex);
			mTransactionSet.insert(f);
		}

		// ok.. now make sure we can locate every input transaction!
		for (uint32_t i=0; i<block.transactionCount; i++)
		{
			BlockTransaction &t = block.transactions[i];
			mTotalInputCount+=t.inputCount;
			mTotalOutputCount+=t.outputCount;
			for (uint32_t j=0; j<t.inputCount; j++)
			{
				BlockInput &input = t.inputs[j];

				if ( input.transactionIndex != 0xFFFFFFFF )
				{
					Hash256 thash(input.transactionHash);
					FileLocation key(thash,0,0,0,0);
					FileLocationSet::iterator found = mTransactionSet.find(key);
					if ( found == mTransactionSet.end() )
					{
						block.warning = true;
						printf("Failed to find transaction!\r\n");
						exit(1);
					}
				}
			}
		}
	}


	uint32_t					mMaxBlocks;	// maximum number of blocks to scan
	uint32_t					mTotalTransactionCount;
	uint32_t					mTotalInputCount;
	uint32_t					mTotalOutputCount;
	std::string					mRootDir;
	uint32_t					mSearchForText;
	uint32_t					mScanCount;							// How many blocks we have processed in the 'forward' scan step.
	uint32_t					mReadCount;
	uint8_t						*mCurrentBlockData;
	uint8_t						mBlockDataBuffer[MAX_BLOCK_SIZE];	// Holds one block of data
	uint32_t					mBlockIndex;						// Index of current file we are processing
	uint32_t					mFileLength;						// Length of the current file we have open...
	FILEVector					mBlockDataFiles;						// The array of files
	BlockHeader					mLastBlockHeader;					// last block header we processed.
	BlockHeaderSet				mBlockHeaderSet;
	uint32_t					mBlockCount;						// Number of total blocks in the blockchain
	BlockHeader					*mBlockChainHeaders;				// Headers for every single block in the blockchain
	BlockImpl					mSingleReadBlock;
	BlockImpl					mSingleTransactionBlock;
	uint32_t					mTransactionCount;
	FILE						*mTextReport;
	uint8_t						mTransactionBlockBuffer[MAX_BLOCK_SIZE];
	FileLocationSet				mTransactionSet;
};

} // end of BLOCK_CHAIN namespace

BlockChain *BlockChain::createBlockChain(const char *rootPath,uint32_t maxBlocks)
{
	BLOCK_CHAIN::BlockChainImpl *b = new BLOCK_CHAIN::BlockChainImpl(rootPath, maxBlocks);
	return static_cast< BlockChain *>(b);
}
