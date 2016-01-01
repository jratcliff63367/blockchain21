#ifndef PUBLIC_KEY_DATABASE_H
#define PUBLIC_KEY_DATABASE_H

#include <stdint.h>

#include "BlockChain.h"

// This class converts the contents of the blocks in the blockchain into
// a database of transactions associated with public keys.
// The contents are written out to two files on disk and can be persisted to 
// perform blockchain analysis


class PublicKeyDatabase
{
public:
	// If 'analyze is true, we load previously build database files for analysis
	static PublicKeyDatabase *create(bool analyze);

	// Add this block to our optimized transaction database
	virtual void addBlock(const BlockChain::Block *b) = 0;

	virtual void buildPublicKeyDatabase(void) = 0;
	
	// Accessors methods for the public key database
	virtual uint32_t getPublicKeyCount(void) = 0;
	virtual void printPublicKey(uint32_t index) = 0;

	virtual void release(void) = 0;

protected:
	virtual ~PublicKeyDatabase(void)
	{
	}
};

#endif
