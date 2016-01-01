#ifndef MEMORY_MAP_H

#define MEMORY_MAP_H

#include <stdint.h>

// Note, there is no Linux implementation of this yet
#ifdef _MSC_VER
class MemoryMap
{
public:

	virtual uint64_t getFileSize(void) = 0;
	virtual void *getBaseAddress(void) = 0;
	virtual void release(void) = 0;

protected:
	virtual ~MemoryMap(void)
	{
	}
};


MemoryMap * createMemoryMap(const char *fileName,uint64_t size,bool createOk);
#endif


#endif
