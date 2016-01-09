#include "logging.h"
#include "BitcoinAddress.h"
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#ifdef _MSC_VER
#include <conio.h>
#pragma warning(disable:4996)
#endif

#define MAXNUMERIC 32  // JWR  support up to 16 32 character long numeric formated strings
#define MAXFNUM    16

static	char  gFormat[MAXNUMERIC*MAXFNUM];
static int32_t    gIndex = 0;

// This is a helper method for getting a formatted numeric output (basically having the commas which makes them easier to read)
const char * formatNumber(int32_t number) // JWR  format this integer into a fancy comma delimited string
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


const char *getDateString(uint32_t _t)
{
	time_t t(_t);
	static char scratch[1024];
	struct tm *gtm = gmtime(&t);
	//	strftime(scratch, 1024, "%m, %d, %Y", gtm);
	sprintf(scratch, "%4d-%02d-%02d", gtm->tm_year + 1900, gtm->tm_mon + 1, gtm->tm_mday);
	return scratch;
}

const char *getTimeString(uint32_t timeStamp)
{
	if (timeStamp == 0)
	{
		return "NEVER";
	}
	static char scratch[1024];
	time_t t(timeStamp);
	struct tm *gtm = gmtime(&t);
	strftime(scratch, 1024, "%m/%d/%Y %H:%M:%S", gtm);
	return scratch;
}



// This is a helper method to handle logging the output from scanning the blockchain
void logMessage(const char *fmt, ...)
{
	static FILE		*gLogFile = NULL;
	char wbuff[2048];
	va_list arg;
	va_start(arg, fmt);
	vsprintf(wbuff, fmt, arg);
	va_end(arg);
	printf("%s", wbuff);
	if (gLogFile == NULL)
	{
		gLogFile = fopen("blockchain.txt", "wb");
	}
	if (gLogFile)
	{
		fprintf(gLogFile, "%s", wbuff);
		fflush(gLogFile);
	}
}


void printReverseHash(const uint8_t hash[32])
{
	if (hash)
	{
		for (uint32_t i = 0; i < 32; i++)
		{
			logMessage("%02x", hash[31 - i]);
		}
	}
	else
	{
		logMessage("NULL HASH");
	}
}

void logBitcoinAddress(const uint8_t address[25])
{
	char temp[512];
	bitcoinAddressToAscii(address, temp, 512);
	logMessage("%s", temp);
}

const char *getBitcoinAddressAscii(const uint8_t address[25])
{
	static char temp[512];
	bitcoinAddressToAscii(address, temp, 512);
	return temp;
}

uint32_t getKey(void)
{
	uint32_t ret = 0;

#ifdef _MSC_VER
	ret = getch();
#endif

	return ret;
}