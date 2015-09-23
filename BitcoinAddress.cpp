#include "BitcoinAddress.h"
#include "Base58.h"
#include "RIPEMD160.h"
#include "SHA256.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _MSC_VER // Disable the stupid ass absurd warning messages from Visual Studio telling you that using stdlib and stdio is 'not valid ANSI C'
#pragma warning(disable:4718)
#pragma warning(disable:4996)
#endif


bool bitcoinPublicKeyToAddress(const uint8_t input[65], // The 65 bytes long ECDSA public key; first byte will always be 0x4 followed by two 32 byte components
							   uint8_t output[25])		// A bitcoin address (in binary( is always 25 bytes long.
{
	bool ret = false;

	if ( input[0] == 0x04)
	{
		uint8_t hash1[32]; // holds the intermediate SHA256 hash computations
		computeSHA256(input,65,hash1);	// Compute the SHA256 hash of the input public ECSDA signature
		output[0] = 0;	// Store a network byte of 0 (i.e. 'main' network)
		computeRIPEMD160(hash1,32,&output[1]);	// Compute the RIPEMD160 (20 byte) hash of the SHA256 hash
		computeSHA256(output,21,hash1);	// Compute the SHA256 hash of the RIPEMD16 hash + the one byte header (for a checksum)
		computeSHA256(hash1,32,hash1); // now compute the SHA256 hash of the previously computed SHA256 hash (for a checksum)
		output[21] = hash1[0];	// Store the checksum in the last 4 bytes of the public key hash
		output[22] = hash1[1];
		output[23] = hash1[2];
		output[24] = hash1[3];
		ret = true;
	}
	return ret;
}

bool bitcoinCompressedPublicKeyToAddress(const uint8_t input[33], // The 33 byte long compressed ECDSA public key; first byte will always be 0x4 followed by the 32 byte component
									     uint8_t output[25])		// A bitcoin address (in binary( is always 25 bytes long.
{
	bool ret = false;

	if ( input[0] == 0x02 || input[0] == 0x03 )
	{
		uint8_t hash1[32]; // holds the intermediate SHA256 hash computations
		computeSHA256(input,33,hash1);	// Compute the SHA256 hash of the input public ECSDA signature
		output[0] = 0;	// Store a network byte of 0 (i.e. 'main' network)
		computeRIPEMD160(hash1,32,&output[1]);	// Compute the RIPEMD160 (20 byte) hash of the SHA256 hash
		computeSHA256(output,21,hash1);	// Compute the SHA256 hash of the RIPEMD16 hash + the one byte header (for a checksum)
		computeSHA256(hash1,32,hash1); // now compute the SHA256 hash of the previously computed SHA256 hash (for a checksum)
		output[21] = hash1[0];	// Store the checksum in the last 4 bytes of the public key hash
		output[22] = hash1[1];
		output[23] = hash1[2];
		output[24] = hash1[3];
		ret = true;
	}
	return ret;
}


bool bitcoinPublicKeyToAscii(const uint8_t input[65], // The 65 bytes long ECDSA public key; first byte will always be 0x4 followed by two 32 byte components
							 char *output,				// The output ascii representation.
							 uint32_t maxOutputLen) // convert a binary bitcoin address into ASCII
{
	bool ret = false;

	output[0] = 0;

	uint8_t hash2[25];

	if ( bitcoinPublicKeyToAddress(input,hash2))
	{
		ret = encodeBase58(hash2,25,true,output,maxOutputLen);
	}
	return ret;
}

bool bitcoinCompressedPublicKeyToAscii(const uint8_t input[33], // The 33 bytes long ECDSA public key
							 char *output,				// The output ascii representation.
							 uint32_t maxOutputLen) // convert a binary bitcoin address into ASCII
{
	bool ret = false;

	output[0] = 0;

	uint8_t hash2[25];

	if ( bitcoinCompressedPublicKeyToAddress(input,hash2))
	{
		ret = encodeBase58(hash2,25,true,output,maxOutputLen);
	}
	return ret;
}


bool bitcoinAsciiToAddress(const char *input,uint8_t output[25]) // convert an ASCII bitcoin address into binary.
{
	bool ret = false;
	uint32_t len = decodeBase58(input,output,25,true);
	if ( len == 25 ) // the output must be *exactly* 25 bytes!
	{
		uint8_t checksum[32];
		computeSHA256(output,21,checksum);
		computeSHA256(checksum,32,checksum);
		if ( output[21] == checksum[0] ||
			 output[22] == checksum[1] ||
			 output[23] == checksum[2] ||
			 output[24] == checksum[3] )
		{
			ret = true; // the cheksum matches!
		}
	}
	return ret;
}


void bitcoinRIPEMD160ToAddress(const uint8_t ripeMD160[20],uint8_t output[25])
{
	uint8_t hash1[32]; // holds the intermediate SHA256 hash computations
	output[0] = 0;	// Store a network byte of 0 (i.e. 'main' network)
	memcpy(&output[1],ripeMD160,20); // copy the 20 byte of the public key address
	computeSHA256(output,21,hash1);	// Compute the SHA256 hash of the RIPEMD16 hash + the one byte header (for a checksum)
	computeSHA256(hash1,32,hash1); // now compute the SHA256 hash of the previously computed SHA256 hash (for a checksum)
	output[21] = hash1[0];	// Store the checksum in the last 4 bytes of the public key hash
	output[22] = hash1[1];
	output[23] = hash1[2];
	output[24] = hash1[3];
}

void bitcoinRIPEMD160ToScriptAddress(const uint8_t ripeMD160[20],uint8_t output[25])
{
	uint8_t hash1[32]; // holds the intermediate SHA256 hash computations
	output[0] = 5;	// Store a network byte of 0 (i.e. 'main' network)
	memcpy(&output[1],ripeMD160,20); // copy the 20 byte of the public key address
	computeSHA256(output,21,hash1);	// Compute the SHA256 hash of the RIPEMD16 hash + the one byte header (for a checksum)
	computeSHA256(hash1,32,hash1); // now compute the SHA256 hash of the previously computed SHA256 hash (for a checksum)
	output[21] = hash1[0];	// Store the checksum in the last 4 bytes of the public key hash
	output[22] = hash1[1];
	output[23] = hash1[2];
	output[24] = hash1[3];
}

bool bitcoinAddressToAscii(const uint8_t address[25],char *output,uint32_t maxOutputLen)
{
	bool ret = false;

	ret = encodeBase58(address,25,true,output,maxOutputLen);

	return ret;
}