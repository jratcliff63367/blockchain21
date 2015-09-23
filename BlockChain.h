#ifndef BLOCK_CHAIN_H

#define BLOCK_CHAIN_H


// This is a minimal C++ code snippet to read the bitcoin block chain one by one into memory.
//
// This code snippet was written by John W. Ratcliff (jratcliffscarab@gmail.com) on June 30, 2013 on a lazy rainy Sunday afternoon 
// It has been recently revised on September 22, 2015.
//
// I wrote this code snippet for two reasons.  First, I just wanted to understand the bitcoin blockchain format myself and
// since I run the full bitcoin-qt client on my machine, I have all the data stored on my hard drive anyway.
//
// I did find this excellent reference online; from which this code was written.  Think of this code snippet as essentially just a reference implementation
// of what is already covered on Jame's blog.
//
// If you find this code snippet useful; you can tip me at this bitcoin address:
//
// BITCOIN TIP JAR: "1NY8SuaXfh8h5WHd4QnYwpgL1mNu9hHVBT"
//
//http://james.lab6.com/2012/01/12/bitcoin-285-bytes-that-changed-the-world/
//
// https://en.bitcoin.it/wiki/Protocol_specification
//
// One problem with Jame's specification is it's not always super clear what the heirachy of the input data is; the classes in this header file
// should hopefully make that a bit more clear.
//
// An important note, a number of the inputs in the blockchain are marked as 'variable length integers' (presumably to 'save space' even though they really don't)
// The variable length integer is capable of being as large as 64 bits but, in actuality, never is.
// That's why all of the integers in the following data structures are 32 bits in size.
//
// A couple of items; sometimes you can run out of blockchain data before you reach the end of the file.  Past a certain point the file just contains zeroes.
// This was not documented in Jame's page; but it is what I encounterd in the input data set.
//
// There are also many cases where the actual data in the block is a lot less than the reported block-length.  I'm going to assume that this too is normal
// and expected.

#include <stdint.h>	// Include stdint.h; available on most compilers but, if not, a copy is provided here for Microsoft Visual Studio
#include <string.h>

#define ONE_BTC 100000000
#define MAX_MULTISIG 5

// This is the interface class for reading the BlockChain
class BlockChain
{
public:
	// Each transaction is comprised of a set of inputs.  This class defines that input data stream.
	class BlockInput
	{
	public:
		BlockInput(void)
		{
			responseScriptLength  = 0;
			responseScript = 0;
			signatureFormat = 0; // unassigned by default
			inputValue = 0;
		}
		const uint8_t	*transactionHash;			// The hash of the input transaction; this a is a pointer to the 32 byte hash
		uint32_t		transactionIndex;			// The index of the transaction
		uint32_t		responseScriptLength;		// the length of the response script. (In theory this could be >32 bits; in practice it never will be.)
		const uint8_t	*responseScript;			// The response script.   This gets run on the bitcoin script virtual machine; see bitcoin docs
		uint32_t		sequenceNumber;				// The 'sequence' number
		uint32_t		signatureFormat;			// Signature format bit flags
		uint64_t		inputValue;					// The amount of value this input represents (based on the valid transaction hash)
	};

	enum KeyType
	{
		KT_UNKNOWN,			// unable to decode the public key
		KT_UNCOMPRESSED_PUBLIC_KEY,
		KT_COMPRESSED_PUBLIC_KEY,
		KT_RIPEMD160,
		KT_TRUNCATED_COMPRESSED_KEY,
		KT_MULTISIG,
		KT_STEALTH,
		KT_SCRIPT_HASH,
		KT_ZERO_LENGTH,
		KT_LAST
	};

	class OutputAddress
	{
	public:
		OutputAddress(void)
		{
			memset(address,0,sizeof(address));
		}
		uint8_t	address[25];
	};

	// Each transaction has a set of outputs; this class defines that output data stream.
	class BlockOutput
	{
	public:
		BlockOutput(void)
		{
			value = 0;
			challengeScriptLength = 0;
			challengeScript = 0;
			keyType = KT_UNKNOWN;
			multiSigFormat = 0;
			for (uint32_t i=0; i<5; i++)
			{
				publicKey[i] = 0;
			}
			signatureCount = 1;
			keyTypeName = "UNKNOWN";
			asciiAddress[0] = 0;
		}
		uint64_t		value;					// value of the output (this is the actual value in BTC fixed decimal notation) @See bitcoin docs
		uint32_t		challengeScriptLength;	// The length of the challenge script  (In theory this could be >32 bits; in practice it never will be.)
		const uint8_t	*challengeScript;		// The contents of the challenge script.  This gets run on the bitcoin script virtual machine; see bitcoin docs
		uint32_t		signatureCount;		// Number of keys in the output
		KeyType			keyType;			// If this is true, then the public key is the 20 byte RIPEMD160 hash rather than the full 65 byte ECDSA hash
		const char		*keyTypeName;		// ASCII representation of the keyType enum
		uint32_t		multiSigFormat;	// bit flags identifying the format of each signature (compressed/uncompressed)
		const uint8_t	*publicKey[MAX_MULTISIG];				// The public key output
		OutputAddress	addresses[MAX_MULTISIG];
		OutputAddress	multisig;			// The multisig address if there is one
		char			asciiAddress[512];		// The full address in ASCII format
	};

	// Each block contains a series of transactions; each transaction with it's own set of inputs and outputs.  
	// This class describes the transaction data.
	class BlockTransaction
	{
	public:
		BlockTransaction(void)
		{
			inputCount = 0;
			inputs = 0;
			outputCount = 0;
			outputs = 0;
			transactionIndex = 0;
		}
		uint32_t		transactionVersionNumber;	// The transaction version number
		uint32_t		inputCount;					// The number of inputs in the block; in theory this could be >32 bits; in practice it never will be.
		BlockInput		*inputs;					// A pointer to the array of inputs
		uint32_t		outputCount;				// The number of outputs in the block.
		BlockOutput		*outputs;					// The outputs in the block; 64bit unsigned int for each output; kind of a fixed decimal representation of bitcoin; see docs
		uint32_t		lockTime;					// The lock-time; currently always set to zero
		// This is data which is computed when the file is parsed; it is not contained in the block chain file itself.
		// This data can uniquely identify the specific transaction with information on how to go back to the seek location on disk and reread it
		uint8_t			transactionHash[32];		// This is the hash for this transaction
		uint32_t		transactionLength;			// The length of the data comprising this transaction.
		uint32_t		fileIndex;					// which blk?????.dat file this transaction is contained in.
		uint32_t		fileOffset;					// the seek file location of this transaction.
		uint32_t		transactionIndex;			// the sequential index number of this transaction
	};

	// This class defines a single block in the block chain.
	class Block
	{
	public:
		Block(void)
		{
			transactions = 0;
			transactionCount = 0;
			nextBlockHash = 0;
		}
		uint32_t		blockLength;				// the length of this block
		uint32_t		blockFormatVersion;			// The block format version
		const uint8_t	*previousBlockHash;			// A pointer to the previous block hash (32 bytes)
		const uint8_t	*merkleRoot;				// A pointer to the MerkleRoot hash
		uint32_t		timeStamp;					// The block timestamp in UNIX epoch time
		uint32_t		bits;						// This is the representation of the target; the value which the hash of the block header must not exceed in order to min the next block
		uint32_t		nonce;						// This is a random number generated during the mining process
		uint32_t		transactionCount;			// Number of transactions on this block
		BlockTransaction *transactions;				// The array of transactions in this block.
		// The following data items are not part of the block chain but are computed by convenience for the caller.
		uint8_t			computedBlockHash[32];		// The computed block hash
		uint32_t		blockIndex;					// Index of this block, the genesis block is considered zero
		uint32_t		totalInputCount;			// Total number of inputs in all transactions.
		uint32_t		totalOutputCount;			// Total number out outputs in all transaction.
		uint32_t		fileIndex;					// Which file index we are on.
		uint32_t		fileOffset;					// The file offset location where this block begins
		uint64_t		blockReward;				// Block redward in BTC
		const uint8_t	*nextBlockHash;				// The hash of the next block in the block chain; null if this is the last block
		bool			warning;					// there was a warning issued while processing this block.
	};

	// Set the search for ASCII text length.  If this value is non-zero, then the parsing code will
	// scan each block for significant amounts of ASCII text (textLen or >) and write the results to a file on disk called
	// AsciiTextReport.txt
	virtual void setSearchTextLength(uint32_t textLen) = 0;

	// Initial scan of the blockchain to build the hash table of blocks in forward order.
	// Contrary to what you might think, or expect, the blocks in the file are not in the order of 
	// 0,1,2,3,4 etc.  The reason for this is that sometimes, while the client is connected to the network, orphan blocks get written
	// out.  So, the only way to know the correct blockchain is to sequentially scan to the last block found.  For each block we compute it's
	// hash and store it into a hash-table.  Then, to build the correct version of the blockchain we have to walk the linked-list backwards from
	// the last block to the first; leaving orphans out of it.
	virtual bool scanBlockChain(uint32_t &lastBlockRead) = 0;

	// Once scanning is completed, we build the blockchain by traversing, as a linked list, the last block to every previous block.
	// This will allow it to successfully skip orphaned blocks.  Return value is the last valid block number encountered.
	virtual uint32_t buildBlockChain(void) = 0;

	// Read this block in
	virtual const Block *readBlock(uint32_t blockIndex) = 0;

	// print the contents of this block
	virtual void printBlock(const Block *b) = 0;

	virtual void release(void) = 0;	// This method releases the block chain interface.

protected:
	virtual ~BlockChain(void)
	{
	}

};


BlockChain *createBlockChain(const char *rootPath,uint32_t maxBlocks);	// Create the BlockChain interface using this root directory for the location of the first 'blk00000.dat' on your hard drive.

#endif
