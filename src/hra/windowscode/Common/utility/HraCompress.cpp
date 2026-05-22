#include <cstring>
#include <string>
#include "HraCompress.h"
#include "Logger.h"

CCompressedBuffer::CCompressedBuffer(size_t initial_size)
	: m_WriteOffset(), m_Size(initial_size), m_OriginalSize(), m_Mode(kModeWrite)
{
	//m_Buffer = new char[m_Size];
    m_Buffer = (char*)malloc(m_Size);
    memset(m_Buffer, 0, m_Size);

	m_DeflateStream.zalloc = Z_NULL;
	m_DeflateStream.zfree = Z_NULL;
	m_DeflateStream.opaque = Z_NULL;

	deflateInit(&m_DeflateStream, Z_BEST_SPEED);

	m_InflateStream.zalloc = Z_NULL;
	m_InflateStream.zfree = Z_NULL;
	m_InflateStream.opaque = Z_NULL;
	m_InflateStream.avail_in = 0;
	m_InflateStream.avail_out = 0;
	m_InflateStream.next_in = Z_NULL;
	inflateInit(&m_InflateStream);
}

CCompressedBuffer::~CCompressedBuffer(void)
{
	//delete[] m_Buffer;
	//m_Buffer = NULL;
    if (m_Buffer)
    {
        free(m_Buffer);
        m_Buffer = NULL;
    }

	(void)deflateEnd(&m_DeflateStream);

	(void)inflateEnd(&m_InflateStream);
}

size_t CCompressedBuffer::Write(const char* buffer, const size_t size)
{
	if (buffer == NULL || size == 0 || m_Mode == kModeRead)
	{
		return 0;
	}
	m_DeflateStream.avail_in = (uInt)size;
	m_DeflateStream.next_in = (unsigned char*)buffer;
	size_t bytes_written = 0;
	do {
		if (m_WriteOffset + ZLIB_CHUNK > m_Size)
		{
			Expand();
		}
		m_DeflateStream.avail_out = ZLIB_CHUNK;
		m_DeflateStream.next_out = (unsigned char*)(m_Buffer + m_WriteOffset);
		deflate(&m_DeflateStream, Z_NO_FLUSH);
		int have = ZLIB_CHUNK - m_DeflateStream.avail_out;
		m_WriteOffset += have;
		bytes_written += have;
	} while (m_DeflateStream.avail_out == 0);

	m_OriginalSize += size;
	return bytes_written;
}

void CCompressedBuffer::Finish(void)
{
	if (m_Mode == kModeRead)
	{
		return;
	}
	m_DeflateStream.avail_in = 0;
	m_DeflateStream.next_in = NULL;

	do {
		if (m_WriteOffset + ZLIB_CHUNK > m_Size)
		{
			Expand();
		}
		m_DeflateStream.avail_out = ZLIB_CHUNK;
		m_DeflateStream.next_out = (unsigned char*)(m_Buffer + m_WriteOffset);
		deflate(&m_DeflateStream, Z_FINISH);
		int have = ZLIB_CHUNK - m_DeflateStream.avail_out;
		m_WriteOffset += have;
	} while (m_DeflateStream.avail_out == 0);

	deflateReset(&m_DeflateStream);

	m_InflateStream.avail_in = (uInt)m_WriteOffset;
	m_InflateStream.next_in = (unsigned char*)m_Buffer;

	m_Mode = kModeRead;
}

size_t CCompressedBuffer::Read(const char* buffer, const size_t size)
{
	if (!buffer || !size)
	{
		return 0;
	}

	int error = Z_OK;
	if (m_WriteOffset == 0) // 表示新对象做解压缩
	{
		m_InflateStream.avail_in = (uInt)size;
		m_InflateStream.next_in = (unsigned char*)buffer;
		size_t sizeReadOffset = 0;
		do {
			if (sizeReadOffset + ZLIB_CHUNK > m_Size)
			{
				Expand();
			}
			m_InflateStream.avail_out = ZLIB_CHUNK;
			m_InflateStream.next_out = (unsigned char*)(m_Buffer + m_InflateStream.total_out);
			error = inflate(&m_InflateStream, Z_NO_FLUSH);
			ASSERT(error >= Z_OK, "uncomprees error (inflate) %d", error);
			int have = ZLIB_CHUNK - m_InflateStream.avail_out;
			sizeReadOffset += have;
		} while (m_InflateStream.avail_out == 0);

		error = inflateEnd(&m_InflateStream);
		ASSERT(error >= Z_OK, "uncomprees error (inflateEnd) %d", error);
		m_WriteOffset = m_InflateStream.total_out; // 通过GetCompressedSize反馈出解压缩大小

		return m_InflateStream.total_out;
	}
	else
	{
		//此模式是同一对象，先压缩，在解压的模式下，buffer为out参数
		if (m_Mode == kModeWrite || m_InflateStream.avail_in == 0)
		{
			return 0;
		}
		size_t bytes_read = 0;

		m_InflateStream.avail_out = (uInt)size;
		m_InflateStream.next_out = (unsigned char*)buffer;

		error = inflate(&m_InflateStream, Z_NO_FLUSH);
		ASSERT(error >= Z_OK, "uncomprees error (inflate) %d", error);
		bytes_read = size - m_InflateStream.avail_out;

		return bytes_read;
	}

	return 0;
}

void CCompressedBuffer::Expand(void)
{
	size_t sizeOldSize = m_Size;
	// 保证扩展的时候大于一个chunk
	if (m_Size < ZLIB_CHUNK)
	{
		m_Size = ZLIB_CHUNK + 1;
	}
	else
	{
		m_Size = m_Size << 1;
	}

	//char* pNewBuffer = new char[m_Size]();
	//memcpy(pNewBuffer, m_Buffer, sizeOldSize);
	//delete[] m_Buffer;
	//m_Buffer = pNewBuffer;
    char* pNewBuffer = (char*)malloc(m_Size);
    memset(pNewBuffer, 0, m_Size);
    if (m_Buffer)
    {
        memcpy(pNewBuffer, m_Buffer, sizeOldSize);
        free(m_Buffer);
        m_Buffer = NULL;
    }
    m_Buffer = pNewBuffer;
}


char* CCompressedBuffer::GetRawBuffer() const { return m_Buffer; }

size_t CCompressedBuffer::GetOriginalSize() const { return m_OriginalSize; }

size_t CCompressedBuffer::GetActualSize() const { return m_Size; }

size_t CCompressedBuffer::GetCompressedSize() const { return m_WriteOffset; }
