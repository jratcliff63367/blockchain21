#ifndef CRC32_H

#define CRC32_H

/*************************************************************************************//**
*
* @brief CRC32 helper functions
*
*****************************************************************************************/

#include <stdint.h>

uint32_t CRC32(uint8_t *buffer, uint32_t len, uint32_t seed);


#endif
