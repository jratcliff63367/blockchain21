#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <malloc.h>
#include <stdint.h>

#include "MemoryMap.h"

#pragma warning(disable:4267)


//********************************************************************************************
//***
//*** A wrapper interface for standard FILE IO services that provides support to read and
//** write 'files' to and from a buffer in memory.
//***
//********************************************************************************************


#include "FileInterface.h"

#define DEFAULT_BUFFER_SIZE 8192
#define BUFFER_GROW_SIZE    1000000 // grow in 1 MB chunks

class MemoryBlock
{
public:
  MemoryBlock(uint64_t size)
  {
	mNextBlock = 0;
	mMemory    = (char *)malloc(size);
	mSize      = size;
	mLen       = 0;
  }

  ~MemoryBlock(void)
  {
	free(mMemory);
  }

  const char * write(const char *mem,uint64_t len,uint64_t &remaining)
  {
	const char *ret = 0;

	if ( (len+mLen) <= mSize )
	{
	  char *dest = &mMemory[mLen];
	  memcpy(dest,mem,len);
	  mLen+=len;
	}
	else
	{
	  uint64_t slen = mSize-mLen;
	  if ( slen )
	  {
		char *dest = &mMemory[mLen];
		memcpy(dest,mem,slen);
		mLen+=slen;
	  }
	  ret = mem+slen;
	  remaining = len-slen;
	  assert( remaining != 0 );
	}
	return ret;
  }

  char * getData(char *dest)
  {
	memcpy(dest,mMemory,mLen);
	dest+=mLen;
	return dest;
  }

	MemoryBlock		*mNextBlock;
	char			*mMemory;
	uint64_t		mLen;
	uint64_t		mSize;

};

class _FILE_INTERFACE 
{
public:
	_FILE_INTERFACE(const char *fname,const char *spec,void *mem,uint64_t len,bool useMemoryMappedFile)
	{
		mMemoryMap = nullptr;
		if (mem == nullptr && useMemoryMappedFile)
		{
			mMemoryMap = createMemoryMap(fname, 0, false);
			if (mMemoryMap)
			{
				mem = mMemoryMap->getBaseAddress();
				len = mMemoryMap->getFileSize();
			}
		}

		mHeadBlock = 0;
		mTailBlock = 0;
		mMyAlloc   = false;
		mRead      = true; // default is read access.
		mFph       = 0;
		mData      = (char *) mem;
		mLen       = len;
		mLoc       = 0;

		if ( spec && _stricmp(spec,"wmem") == 0 )
		{
			mRead = false;
			if ( mem == 0 || len == 0 )
			{
				mHeadBlock = new MemoryBlock(DEFAULT_BUFFER_SIZE);
				mTailBlock = mHeadBlock;
				mData = 0;
				mLen  = 0;
				mMyAlloc = true;
			}
		}
		if ( mData == 0 && mHeadBlock == 0 )
		{
			mFph = fopen(fname,spec);
		}
		strncpy(mName,fname,512);
	}

	~_FILE_INTERFACE(void)
	{
		if ( mMyAlloc )
		{
			free(mData);
			MemoryBlock *mb = mHeadBlock;
			while ( mb )
			{
				MemoryBlock *next = mb->mNextBlock;
				delete mb;
				mb = next;
			}
		}
		if ( mFph )
		{
			fclose(mFph);
		}
		if (mMemoryMap)
		{
			mMemoryMap->release();
		}
	}

	uint64_t read(char *data,uint64_t size)
	{
		uint64_t ret = 0;
		if ( (mLoc+size) <= mLen )
		{
			memcpy(data, &mData[mLoc], size );
			mLoc+=size;
			ret = 1;
		}
		return ret;
	}

	bool usesMemoryMappedFile(void) const
	{
		return mMemoryMap ? true : false;
	}

	void * getCurrentMemoryLocation(void) const
	{
		void * ret = 0;
		if (mData)
		{
			ret = &mData[mLoc];
		}
		return ret;
	}

	void validateLen(void)
	{
		if ( mHeadBlock )
		{
			uint64_t slen = 0;
			MemoryBlock *mb = mHeadBlock;
			while (mb)
			{
				slen += mb->mLen;
				mb = mb->mNextBlock;
			}
		assert( slen == mLoc );
		}
	}

	uint64_t write(const char *data,uint64_t size)
	{
		uint64_t ret = 0;

		if ( mMyAlloc )
		{
			#ifdef _DEBUG
			validateLen();
			#endif
			uint64_t remaining;
			data = mTailBlock->write(data,size,remaining);
			while ( data )
			{
				uint64_t _size = remaining;
				MemoryBlock *block = new MemoryBlock(BUFFER_GROW_SIZE);
				mTailBlock->mNextBlock = block;
				mTailBlock = block;
				data = mTailBlock->write(data,_size,remaining);
			}
			mLoc+=size;
			#ifdef _DEBUG
			validateLen();
			#endif
			ret = 1;
		}
		else
		{
			if ( (mLoc+size) <= mLen )
			{
				memcpy(&mData[mLoc],data,size);
				mLoc+=size;
				ret = 1;
			}
		}
		return ret;
	}

	uint64_t read(void *buffer,uint64_t size,uint64_t count)
	{
		uint64_t ret = 0;
		if ( mFph )
		{
			ret = fread(buffer,size,count,mFph);
		}
		else
		{
			char *data = (char *)buffer;
			for (uint64_t i=0; i<count; i++)
			{
				if ( (mLoc+size) <= mLen )
				{
					read(data,size);
					data+=size;
					ret++;
				}
				else
				{
					break;
				}
			}
		}
		return ret;
	}

	uint64_t write(const void *buffer,uint64_t size,uint64_t count)
	{
		uint64_t ret = 0;

		if ( mFph )
		{
			ret = fwrite(buffer,size,count,mFph);
		}
		else
		{
			const char *data = (const char *)buffer;
			for (uint64_t i=0; i<count; i++)
			{
				if ( write(data,size) )
				{
					data+=size;
					ret++;
				}
				else
				{
					break;
				}
			}
		}
		return ret;
	}

	uint64_t writeString(const char *str)
	{
		uint64_t ret = 0;
		if ( str )
		{
			uint64_t len = strlen(str);
			ret = write(str,len, 1 );
		}
		return ret;
	}


	uint64_t  flush(void)
	{
		uint64_t ret = 0;
		if ( mFph )
		{
			ret = fflush(mFph);
		}
		return ret;
	}


	uint64_t seek(uint64_t loc,int mode)
	{
		uint64_t ret = 0;
		if ( mFph )
		{
			ret = _fseeki64(mFph,loc,mode);
		}
		else
		{
			if ( mode == SEEK_SET )
			{
				if ( loc <= mLen )
				{
					mLoc = loc;
					ret = 1;
				}
			}
			else if ( mode == SEEK_END )
			{
				mLoc = mLen;
			}
			else
			{
				assert(0);
			}
		}
		return ret;
	}

	uint64_t tell(void)
	{
		uint64_t ret = 0;
		if ( mFph )
		{
			ret = ftell(mFph);
		}
		else
		{
			ret = mLoc;
		}
		return ret;
	}

	uint64_t myputc(char c)
	{
		uint64_t ret = 0;
		if ( mFph )
		{
			ret = fputc(c,mFph);
		}
		else
		{
			ret = write(&c,1);
		}
		return ret;
	}

	uint64_t eof(void)
	{
		uint64_t ret = 0;
		if ( mFph )
		{
			ret = feof(mFph);
		}
		else
		{
			if ( mLoc >= mLen )
				ret = 1;
		}
		return ret;
	}

	uint64_t  error(void)
	{
		uint64_t ret = 0;
		if ( mFph )
		{
			ret = ferror(mFph);
		}
		return ret;
	}

	void * getMemBuffer(uint64_t &outputLength)
	{
		outputLength = mLoc;

		if ( mHeadBlock && mLoc > 0 )
		{
			assert(mData==0);
			mData = (char *)malloc(mLoc);
			char *dest = mData;
			MemoryBlock *mb = mHeadBlock;
			while ( mb )
			{
				dest = mb->getData(dest);
				MemoryBlock *next = mb->mNextBlock;
				delete mb;
				mb = next;
			}
			mHeadBlock = 0;
			mTailBlock = 0;
		}
		return mData;
	}

	void  myclearerr(void)
	{
		if ( mFph )
		{
			clearerr(mFph);
		}
	}

	FILE 					*mFph;
	char				*mData;
	uint64_t				mLen;
	uint64_t				mLoc;
	bool				mRead;
	char				mName[512];
	bool				mMyAlloc;
	MemoryBlock			*mHeadBlock;
	MemoryBlock			*mTailBlock;
	MemoryMap			*mMemoryMap;
};

FILE_INTERFACE * fi_fopen(const char *fname,const char *spec,void *mem,uint64_t len,bool useMemoryMappedFile)
{
	_FILE_INTERFACE *ret = 0;
	ret = new _FILE_INTERFACE(fname,spec,mem,len, useMemoryMappedFile);

	if ( mem == 0 && ret->mData == 0 && ret->mHeadBlock == 0 )
	{
		if ( ret->mFph == 0 )
		{
			delete ret;
			ret = 0;
		}
	}
	return (FILE_INTERFACE *)ret;
}

uint64_t  fi_fclose(FILE_INTERFACE *_file)
{
	uint64_t ret = 0;
	if ( _file )
	{
		_FILE_INTERFACE *file = (_FILE_INTERFACE *)_file;
		delete file;
	}
	return ret;
}

void  fi_clearerr(FILE_INTERFACE *_fph)
{
	_FILE_INTERFACE *fph = (_FILE_INTERFACE *)_fph;
	if ( fph )
	{
		fph->myclearerr();
	}
}

uint64_t fi_fread(void *buffer,uint64_t size,uint64_t count,FILE_INTERFACE *_fph)
{
	_FILE_INTERFACE *fph = (_FILE_INTERFACE *)_fph;
	uint64_t ret = 0;
	if ( fph )
	{
		ret = fph->read(buffer,size,count);
	}
	return ret;
}

uint64_t fi_fwrite(const void *buffer,uint64_t size,uint64_t count,FILE_INTERFACE *_fph)
{
	_FILE_INTERFACE *fph = (_FILE_INTERFACE *)_fph;
	uint64_t ret = 0;
	if ( fph )
	{
		ret = fph->write(buffer,size,count);
	}
	return ret;
}

uint64_t  fi_fprintf(FILE_INTERFACE *_fph,const char *fmt,...)
{
	_FILE_INTERFACE *fph = (_FILE_INTERFACE *)_fph;
	uint64_t ret = 0;

	char buffer[2048];
	buffer[2047] = 0;
	_vsnprintf(buffer,2047, fmt, (char *)(&fmt+1));

	if ( fph )
	{
		ret = fph->writeString(buffer);
	}

	return ret;
}


uint64_t fi_fflush(FILE_INTERFACE *_fph)
{
	_FILE_INTERFACE *fph = (_FILE_INTERFACE *)_fph;
	uint64_t ret = 0;
	if ( fph )
	{
		ret = fph->flush();
	}
	return ret;
}


uint64_t        fi_fseek(FILE_INTERFACE *_fph,uint64_t loc,int mode)
{
	_FILE_INTERFACE *fph = (_FILE_INTERFACE *)_fph;
	uint64_t ret = 0;
	if ( fph )
	{
		ret = fph->seek(loc,mode);
	}
	return ret;
}

uint64_t        fi_ftell(FILE_INTERFACE *_fph)
{
	_FILE_INTERFACE *fph = (_FILE_INTERFACE *)_fph;
	uint64_t ret = 0;
	if ( fph )
	{
		ret = fph->tell();
	}
	return ret;
}

uint64_t        fi_fputc(char c,FILE_INTERFACE *_fph)
{
	_FILE_INTERFACE *fph = (_FILE_INTERFACE *)_fph;
	uint64_t ret = 0;
	if ( fph )
	{
		ret = fph->myputc(c);
	}
	return ret;
}

uint64_t        fi_fputs(const char *str,FILE_INTERFACE *_fph)
{
	_FILE_INTERFACE *fph = (_FILE_INTERFACE *)_fph;
	uint64_t ret = 0;
	if ( fph )
	{
		ret = fph->writeString(str);
	}
	return ret;
}

uint64_t        fi_feof(FILE_INTERFACE *_fph)
{
  _FILE_INTERFACE *fph = (_FILE_INTERFACE *)_fph;
	uint64_t ret = 0;
	if ( fph )
	{
		ret = fph->eof();
	}
	return ret;
}

uint64_t        fi_ferror(FILE_INTERFACE *_fph)
{
	_FILE_INTERFACE *fph = (_FILE_INTERFACE *)_fph;
	uint64_t ret = 0;
	if ( fph )
	{
		ret = fph->error();
	}
	return ret;
}

void *     fi_getMemBuffer(FILE_INTERFACE *_fph,uint64_t *outputLength)
{
	_FILE_INTERFACE *fph = (_FILE_INTERFACE *)_fph;
	*outputLength = 0;
	void * ret = 0;
	if ( fph && outputLength )
	{
	ret = fph->getMemBuffer(*outputLength);
	}
	return ret;
}

bool				fi_usesMemoryMappedFile(FILE_INTERFACE *_fph)
{
	_FILE_INTERFACE *fph = (_FILE_INTERFACE *)_fph;
	return fph->usesMemoryMappedFile();
}

void *	fi_getCurrentMemoryLocation(FILE_INTERFACE *_fph) // only valid for memory based files; but will return the address in memory of the current file location
{
	_FILE_INTERFACE *fph = (_FILE_INTERFACE *)_fph;
	return fph->getCurrentMemoryLocation();
}

