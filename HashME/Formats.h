#pragma once
#include "Common.h"
#include "Language.h"
#include "MD2.h"
#include "MD4.h"
#include "MD5.h"
#include "SHA1.h"
#include "SHA2.h"
#include "SHA3.h"
#include "CRC.h"


//const TCHAR* Months[] = { L"January", L"February", L"March", L"April", L"May",L"June",L"July",L"August",L"September",L"October",L"November",L"December" };
//
//const TCHAR* DaysInWeek[] = { L"Sunday",L"Monday", L"Tuesday", L"Wednesday", L"Thursday", L"Friday",L"Saturday" };
//
//const TCHAR* AM_PM[] = { L"AM",L"PM" };

const char HexStringLowerCase[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9','a', 'b', 'c', 'd', 'e', 'f' };
const char HexStringUpperCase[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9','A', 'B', 'C', 'D', 'E', 'F' };
static TCHAR FileNamePrefix[5] = { 0x5C,0x5C,0x3F,0x5C,NULL };

//HANDLE ghEvents = NULL;
//DWORD WINAPI md5_ThreadProc(LPVOID);
//DWORD WINAPI sha1_ThreadProc(LPVOID);
//DWORD WINAPI sha256_ThreadProc(LPVOID);
//DWORD WINAPI sha512_ThreadProc(LPVOID);
//DWORD WINAPI crc_ThreadProc(LPVOID);


extern TCHAR* uCharToHexStringFormat(unsigned char* OriginCode, TCHAR* HexResult, int CodeLen, int BufferLen, bool Uppercase);		//Transfer a unsigned char[] to Hex-based format TCHAR[] (wchar[] here) as a string for output
extern TCHAR* uIntToHexStringFormat(uint32_t InputNumber, TCHAR* HexResult, int CodeLen, int BufferLen, bool Uppercase);
extern void Link2String(TCHAR* CharArray1, TCHAR* CharArray2, TCHAR* ResultBuffer, uint32_t BufferSize, uint32_t Offset);
extern size_t FormatTextToMemCube(TCHAR* TextToFormat, unsigned char* Result, int TextLen, int CodeIndex);
extern void FormatMemResultOutput(TCHAR* OutputBuffer, TCHAR* Input, HASH_ctx* Result, Settings* s);
extern void FormatFileResultOutput(TCHAR* OutputBuffer, TCHAR* Filepath, TCHAR* Filesize, HASH_ctx* Result, Settings* s);
extern void FormatFileErrorOutput(TCHAR* OutputBuffer, TCHAR* Filepath);
extern void FormatInformationOutput(TCHAR* OutputBuffer, TCHAR* Info);
extern void FormatInfoLableFinishOutput(TCHAR* OutputBuffer, uint32_t DeltaTime);
extern void FormatInfoLableOutput(TCHAR* InfoOutputBuffer, uint32_t bufferlen, ProgressStrcure* p);
extern void *swap_uint32_memcpy(void *to, const void *from, size_t length);
extern void *swap_uint64_memcpy(void *to, const void *from, size_t length);
extern bool File_Hash(HANDLE hFile, uint64_t FileSize, HWND PGBar, HWND InfoLable, ProgressStrcure* pb, HASH_ctx* ctx, Settings* s, bool* stp);