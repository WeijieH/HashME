#pragma once

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <windows.h>
#include <tchar.h>
#include <shellapi.h>
#include <commctrl.h>

#pragma comment(lib, "comctl32")

//asm optimal
#if !defined(WIN64) && !defined(_WIN64) && !defined(__WIN64__)
#define x86ASM
#endif
//Lang
//#define CHS

#ifndef CHS
#define ENG
#endif


//Define macros
#define ROTL32(dword, n) ((dword) << (n) ^ ((dword) >> (32 - (n))))
#define ROTR32(dword, n) ((dword) >> (n) ^ ((dword) << (32 - (n))))
#define ROTL64(qword, n) ((qword) << (n) ^ ((qword) >> (64 - (n))))
#define ROTR64(qword, n) ((qword) >> (n) ^ ((qword) << (64 - (n))))



//字节序的小头和大头的问题
#define LITTLE_ENDIAN  0x0123
#define BIG_ENDIAN     0x3210

#ifndef BYTES_ORDER
#define BYTES_ORDER    LITTLE_ENDIAN
#endif

#ifndef SWAP_UINT16
#define SWAP_UINT16(x)  ((((x) & 0xff00) >>  8) | (((x) & 0x00ff) <<  8))
#endif
#ifndef SWAP_UINT32
#define SWAP_UINT32(x)  ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) | \
    (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))
#endif
#ifndef SWAP_UINT64
#define SWAP_UINT64(x)  ((((x) & 0xff00000000000000) >> 56) | (((x) & 0x00ff000000000000) >>  40) | \
    (((x) & 0x0000ff0000000000) >> 24) | (((x) & 0x000000ff00000000) >>  8) | \
    (((x) & 0x00000000ff000000) << 8 ) | (((x) & 0x0000000000ff0000) <<  24) | \
    (((x) & 0x000000000000ff00) << 40 ) | (((x) & 0x00000000000000ff) <<  56))
#endif

#define Encode_Unicode		1
#define Encode_ANSI			2
#define Encode_UTF8			3
#define Encode_UTF16		4
#define Encode_UTF32		5
#define Encode_UCS4			6



//Output textbox text buffer length
#define OUTPUT_TEXT_BUFFER_SIZE   32 * 1024

//Output lable text buffer
static TCHAR OUTPUT_LABLE_BUFFER[60] = { 0 };

//Read block size
#define READ_BUFFER_SIZE  16 * 1024

//HASH每次处理的BLOCK的大小
#define MD2_BLOCK_SIZE  16
#define MD4_BLOCK_SIZE  64
#define MD5_BLOCK_SIZE  64
#define SHA1_BLOCK_SIZE  64
#define SHA224_BLOCK_SIZE  64
#define SHA256_BLOCK_SIZE  64
#define SHA384_BLOCK_SIZE  128
#define SHA512_BLOCK_SIZE  128



//HASH的结果数据长度
#define MD2_HASH_SIZE  16
#define MD4_HASH_SIZE  16
#define MD5_HASH_SIZE  16
#define SHA1_HASH_SIZE  20
#define SHA224_HASH_SIZE  28
#define SHA256_HASH_SIZE  32
#define SHA384_HASH_SIZE  48
#define SHA512_HASH_SIZE  64
#define CRC32_HASH_SIZE  4
#define CRC16_HASH_SIZE  2

#define MD2_HASH_RESULT_TEXT_SIZE  MD2_HASH_SIZE * 2 + 1
#define MD4_HASH_RESULT_TEXT_SIZE  MD4_HASH_SIZE * 2 + 1
#define MD5_HASH_RESULT_TEXT_SIZE  MD5_HASH_SIZE * 2 + 1
#define SHA1_HASH_RESULT_TEXT_SIZE  SHA1_HASH_SIZE * 2 + 1
#define SHA224_HASH_RESULT_TEXT_SIZE  SHA224_HASH_SIZE * 2 + 1
#define SHA256_HASH_RESULT_TEXT_SIZE  SHA256_HASH_SIZE * 2 + 1
#define SHA384_HASH_RESULT_TEXT_SIZE  SHA384_HASH_SIZE * 2 + 1
#define SHA512_HASH_RESULT_TEXT_SIZE  SHA512_HASH_SIZE * 2 + 1
#define CRC32_HASH_RESULT_TEXT_SIZE  CRC32_HASH_SIZE * 2 + 1
#define CRC16_HASH_RESULT_TEXT_SIZE  CRC16_HASH_SIZE * 2 + 1

//Save hash results
typedef struct HASH_ctx
{
	//处理的数据的长度
	uint64_t length_;
	//还没有处理的数据长度
	uint64_t unprocessed_;
	uint64_t MD2_unprocessed_;
	uint64_t MD4_unprocessed_;
	uint64_t MD5_unprocessed_;
	uint64_t SHA1_unprocessed_;
	uint64_t SHA224_unprocessed_;
	uint64_t SHA256_unprocessed_;
	uint64_t SHA384_unprocessed_;
	uint64_t SHA512_unprocessed_;
	uint64_t CRC_unprocessed_;
	
	//取得的HASH结果(中间数据)
	uint8_t	  MD2_hash_[48];
	uint32_t  MD4_hash_[4];
	uint32_t  MD5_hash_[4];
	uint32_t  SHA1_hash_[5];
	uint32_t  SHA224_hash_[8];
	uint32_t  SHA256_hash_[8];
	uint64_t  SHA384_hash_[8];
	uint64_t  SHA512_hash_[8];
	uint32_t  CRC32_hash_;
	uint16_t  CRC16_hash_;

	//Save unsigned char[] result
	unsigned char MD2_result[MD2_HASH_SIZE] = { 0 };
	unsigned char MD4_result[MD4_HASH_SIZE] = { 0 };
	unsigned char MD5_result[MD5_HASH_SIZE] = { 0 };
	unsigned char SHA1_result[SHA1_HASH_SIZE] = { 0 };
	unsigned char SHA224_result[SHA224_HASH_SIZE] = { 0 };
	unsigned char SHA256_result[SHA256_HASH_SIZE] = { 0 };
	unsigned char SHA384_result[SHA384_HASH_SIZE] = { 0 };
	unsigned char SHA512_result[SHA512_HASH_SIZE] = { 0 };

	//Save finial results for output
	TCHAR MD2_HexResult_Output[MD2_HASH_RESULT_TEXT_SIZE] = { 0 };
	TCHAR MD4_HexResult_Output[MD4_HASH_RESULT_TEXT_SIZE] = { 0 };
	TCHAR MD5_HexResult_Output[MD5_HASH_RESULT_TEXT_SIZE] = { 0 };
	TCHAR SHA1_HexResult_Output[SHA1_HASH_RESULT_TEXT_SIZE] = { 0 };
	TCHAR SHA224_HexResult_Output[SHA224_HASH_RESULT_TEXT_SIZE] = { 0 };
	TCHAR SHA256_HexResult_Output[SHA256_HASH_RESULT_TEXT_SIZE] = { 0 };
	TCHAR SHA384_HexResult_Output[SHA384_HASH_RESULT_TEXT_SIZE] = { 0 };
	TCHAR SHA512_HexResult_Output[SHA512_HASH_RESULT_TEXT_SIZE] = { 0 };
	TCHAR CRC32_HexResult_Output[CRC32_HASH_RESULT_TEXT_SIZE] = { 0 };
	TCHAR CRC16_HexResult_Output[CRC16_HASH_RESULT_TEXT_SIZE] = { 0 };

	//File modify time
	SYSTEMTIME SysFileT;
} HASH_ctx;

static HASH_ctx ctx;
static HASH_ctx ctx_mem;
//Global variables
typedef struct ProgressStrcure
{	
	uint64_t TotalBytesToProcess = 0;	
	uint64_t BytesProcessed = 0;	
	uint64_t Checker = 0;
	uint32_t TotalFileToProcess = 0;
	uint32_t FileUnderProcessing = 0;
	TCHAR FilenameUnderProcessing[_MAX_FNAME + _MAX_EXT] = { 0 };
	uint32_t CurrentFilePrecetage = 0;
	TCHAR **szFilepath = NULL;				//This is the file name table
	TCHAR **szPrefixedFilepath = NULL;		//This is the prefixed file name table, use this table to read file so can break 255 char limit for file names
	uint64_t *FileSize = NULL;				//This is the file size table
	TCHAR **szFileSizeText = NULL;			//This is the file size table for output
}ProgressStrcure;

typedef struct Settings
{
	bool time = false;
	bool MD2 = false;
	bool MD4 = false;
	bool MD5 = true;
	bool SHA1 = true;
	bool SHA224 = false;
	bool SHA256 = true;
	bool SHA384 = false;
	bool SHA512 = false;
	bool CRC32 = true;
	bool CRC16 = false;
	//Character encoding
	int CharEncoding = Encode_UTF8;	
	//result case, true for Uppercase
	bool LetterCase = true;
	//Single instance
	bool singleinstance = false;
	//Right click menu
	bool ShellMenu = false;
	//Use reg or not
	bool UseReg = false;
}Settings;


static TCHAR OUTPUT_TEXT_BUFFER[OUTPUT_TEXT_BUFFER_SIZE] = { 0 };

static bool STOP = false;
static bool WORKING = false;

static HFONT hFont9 = NULL;
static HFONT hFont8 = NULL;

static LARGE_INTEGER OriFileLengh;
static TCHAR *szInputText = NULL;

static TCHAR tempFilename[_MAX_FNAME] = { 0 };
static TCHAR tempFileextn[_MAX_EXT] = { 0 };
