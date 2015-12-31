#ifndef LOGGING_H
#define LOGGING_H

#include <stdint.h>

// Utility and helper functions to print and log output
const char * formatNumber(int32_t number); // JWR  format this integer into a fancy comma delimited string
const char *getDateString(uint32_t t);
const char *getTimeString(uint32_t timeStamp);
void printReverseHash(const uint8_t hash[32]);
void logMessage(const char *fmt, ...);
void logBitcoinAddress(const uint8_t address[25]);

#endif
