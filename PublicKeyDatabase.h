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
	static PublicKeyDatabase *create(void);

	// Add this block to our optimized transaction database
	virtual void addBlock(const BlockChain::Block *b) = 0;

	// Once all of the blocks have been processed and transactions accumulated, we now
	// can build the public key database; this collates all transaction inputs and outupts
	// relative to each bitcoin address.
	// The purpose of this is so that we can later use this pre-processed database to perform
	// relatively high speed queries against the blockchain.  Most of the interesting data we want to 
	// collect is relative to public key addresses
	// Creates essentially two arrays on disk; an array of all transactions in the blockchain over time
	// and an array of all unique bitcoin public key addresses over time.
	virtual void buildPublicKeyDatabase(void) = 0;

	virtual void release(void) = 0;

protected:
	virtual ~PublicKeyDatabase(void)
	{
	}
};

#endif
