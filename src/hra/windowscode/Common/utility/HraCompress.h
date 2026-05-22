#pragma once
#ifndef _GLTX_COMPRESSED_MEMORY_BUFFER_H_
#define _GLTX_COMPRESSED_MEMORY_BUFFER_H_

#include "Logger.h"
#include "zlib/zconf.h"
#include "zlib/zlib.h"
#include <cstddef>

#define ZLIB_CHUNK 16384
#define COMPRESS_CACHE_MAX_SIZE  (1 << 21)  //2MB

class HRA_UTILITY_EXPORT CCompressedBuffer {
public:
	const static int kModeWrite = 0;
	const static int kModeRead = 1;

	explicit CCompressedBuffer(size_t initial_size = ZLIB_CHUNK);
	~CCompressedBuffer(void);

	void Finish(void);                                    // finish write mode
	size_t Write(const char *buffer, const size_t size);  // write data to internal buffer
	size_t Read(const char *buffer, const size_t size);   // we can only read after Finish()
	char *GetRawBuffer(void) const;                       // return internal buffer, you should use
	// Read() instead
	size_t GetOriginalSize(void) const;                   // return total original size
	size_t GetActualSize(void) const;                     // return actual size of internal buffer
	size_t GetCompressedSize(void) const;                 // return return total compressed size of data

private:
	char *m_Buffer;    // internal buffer
	size_t m_WriteOffset;  // write offset
	size_t m_Size;     // current buffer size
	size_t m_OriginalSize;    // original size
	z_stream m_DeflateStream;  // deflate z_stream
	z_stream m_InflateStream;  // inflate z_stream

	int m_Mode;

	void Expand(void);
};

#endif
