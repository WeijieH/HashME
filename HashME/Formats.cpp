#include "Formats.h"





TCHAR* uCharToHexStringFormat(unsigned char* OriginCode, TCHAR* HexResult, int CodeLen, int BufferLen, bool Uppercase)
{	
	if (BufferLen < 2 * CodeLen +1)
		return NULL;
	static int i = 0;
	static int div = 0;
	static int res = 0;
	if (Uppercase)
	{
		for (i = 0; i < CodeLen; i++)
		{
			div = OriginCode[i] / 16;
			res = OriginCode[i] % 16;
			HexResult[2 * i] = (TCHAR)HexStringUpperCase[div];
			HexResult[2 * i + 1] = (TCHAR)HexStringUpperCase[res];
		}
	}
	else
	{
		for (i = 0; i < CodeLen; i++)
		{
			div = OriginCode[i] / 16;
			res = OriginCode[i] % 16;
			HexResult[2 * i] = (TCHAR)HexStringLowerCase[div];
			HexResult[2 * i + 1] = (TCHAR)HexStringLowerCase[res];
		}
	}
	HexResult[CodeLen * 2] = NULL;
	return HexResult;
}

TCHAR* uIntToHexStringFormat(uint32_t InputNumber, TCHAR* HexResult, int CodeLen, int BufferLen, bool Uppercase)
{
	if (BufferLen < 2 * CodeLen + 1)
		return NULL;
	static int i;
	static int res;
	uint32_t temp = InputNumber;
	if (Uppercase)
	{
		for (i = 2 * CodeLen - 1; i >= 0; i--)
		{
			res = temp & 0x0000000F;
			HexResult[i] = (TCHAR)HexStringUpperCase[res];
			temp >>= 4;
		}
	}
	else
	{
		for (i = 2 * CodeLen - 1; i >= 0; i--)
		{		
			res = temp & 0x0000000F;
			HexResult[i] = (TCHAR)HexStringLowerCase[res];
			temp >>= 4;
		}
	}
	HexResult[2 * CodeLen] = NULL;
	return HexResult;
}

void Link2String(TCHAR* CharArray1, TCHAR* CharArray2, TCHAR* ResultBuffer, uint32_t BufferSize, uint32_t Offset)
{
	if (Offset > BufferSize)
		return;
	size_t A1 = _tcslen(CharArray1);
	size_t A2 = _tcslen(CharArray2);
	wmemmove_s((ResultBuffer + Offset), BufferSize, CharArray1, A1);
	wmemmove_s((ResultBuffer + Offset + A1), BufferSize, CharArray2, A2);
	ResultBuffer[Offset + A1 + A2] = NULL;
	return;
}

size_t FormatTextToMemCube(TCHAR* TextToFormat, unsigned char* Result, int ResultBufferLen, int CodeIndex)
{	
	size_t cubesize = 0;
	switch (CodeIndex)
	{
	case Encode_ANSI:
	{		
		WideCharToMultiByte(CP_ACP, NULL, TextToFormat, -1, (char*)Result, ResultBufferLen, NULL, NULL);
		cubesize = strlen((char*)Result);
		break;
	}
	case Encode_UTF8:
	{		
		WideCharToMultiByte(CP_UTF8, NULL, TextToFormat, -1, (char*)Result, ResultBufferLen, NULL, NULL);
		cubesize = strlen((char*)Result);
		break;
	}
	default:		//Unicode or UCS_2
	{
		size_t memsize = _tcslen(TextToFormat);
		cubesize = 2 * memsize;
		memcpy(Result, TextToFormat, cubesize);
		break;
	}
	}

	return cubesize;
}

void FormatMemResultOutput(TCHAR* OutputBuffer, TCHAR* Input, HASH_ctx* Result, Settings* s)
{
	wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Output_input_text);
	wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Input);
	switch (s->CharEncoding)
	{
	case Encode_Unicode:
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Output_unicode_text);
		break;
	case Encode_ANSI:
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Output_ansi_text);
		break;
	case Encode_UTF8:
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Output_utf8_text);
		break;
	default:
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\"\r\n");
		break;
	}
	if (s->MD5)
	{
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"MD5:\t");
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Result->MD5_HexResult_Output);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
	}
	if (s->MD2)
	{
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"MD2:\t");
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Result->MD2_HexResult_Output);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
	}
	if (s->MD4)
	{
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"MD4:\t");
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Result->MD4_HexResult_Output);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
	}
	if (s->SHA1)
	{
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"SHA1:\t");
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Result->SHA1_HexResult_Output);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
	}
	if (s->SHA224)
	{
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"SHA224:\t");
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Result->SHA224_HexResult_Output);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
	}
	if (s->SHA256)
	{
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"SHA256:\t");
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Result->SHA256_HexResult_Output);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
	}
	if (s->SHA384)
	{
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"SHA384:\t");
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Result->SHA384_HexResult_Output);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
	}
	if (s->SHA512)
	{
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"SHA512:\t");
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Result->SHA512_HexResult_Output);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
	}
	if (s->CRC32)
	{
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"CRC32:\t");
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Result->CRC32_HexResult_Output);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
	}
	if (s->CRC16)
	{
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"CRC16:\t");
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Result->CRC16_HexResult_Output);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
	}
	wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
}

void FormatFileResultOutput(TCHAR* OutputBuffer, TCHAR* Filepath, TCHAR* Filesize, HASH_ctx* Result, Settings* s)
{	
	TCHAR temp[5] = { 0 };

	wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Output_file_text);
	wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Filepath);
	wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
	wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Output_size_text);
	wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Filesize);
	wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Output_byte_text);
	if (s->time)
	{
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Output_modified_text);
		_ui64tow_s(Result->SysFileT.wMonth, temp, 5, 10);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, temp);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"/");
		_ui64tow_s(Result->SysFileT.wDay, temp, 5, 10);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, temp);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"/");
		_ui64tow_s(Result->SysFileT.wYear, temp, 5, 10);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, temp);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L" ");

		if (Result->SysFileT.wHour < 10)
			wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"0");
		_ui64tow_s(Result->SysFileT.wHour, temp, 5, 10);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, temp);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L":");

		if (Result->SysFileT.wMinute < 10)
			wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"0");
		_ui64tow_s(Result->SysFileT.wMinute, temp, 5, 10);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, temp);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L":");

		if (Result->SysFileT.wSecond < 10)
			wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"0");
		_ui64tow_s(Result->SysFileT.wSecond, temp, 5, 10);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, temp);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
	}
	if (s->MD2)
	{
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"MD2:\t");
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Result->MD2_HexResult_Output);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
	}
	if (s->MD4)
	{
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"MD4:\t");
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Result->MD4_HexResult_Output);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
	}
	if (s->MD5)
	{
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"MD5:\t");
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Result->MD5_HexResult_Output);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
	}
	if (s->SHA1)
	{
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"SHA1:\t");
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Result->SHA1_HexResult_Output);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
	}
	if (s->SHA224)
	{
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"SHA224:\t");
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Result->SHA224_HexResult_Output);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
	}
	if (s->SHA256)
	{
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"SHA256:\t");
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Result->SHA256_HexResult_Output);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
	}
	if (s->SHA384)
	{
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"SHA384:\t");
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Result->SHA384_HexResult_Output);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
	}
	if (s->SHA512)
	{
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"SHA512:\t");
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Result->SHA512_HexResult_Output);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
	}
	if (s->CRC32)
	{
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"CRC32:\t");
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Result->CRC32_HexResult_Output);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
	}
	if (s->CRC16)
	{
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"CRC16:\t");
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Result->CRC16_HexResult_Output);
		wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
	}
	wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n");
}

void FormatFileErrorOutput(TCHAR* OutputBuffer, TCHAR* Filepath)
{
	wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Output_file_text);
	wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Filepath);
	wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Output_failtoread_text);
}

void FormatInformationOutput(TCHAR* OutputBuffer, TCHAR* Info)
{
	wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, Info);
	wcscat_s(OutputBuffer, OUTPUT_TEXT_BUFFER_SIZE, L"\r\n\r\n");
}

void FormatInfoLableFinishOutput(TCHAR* OutputBuffer, uint32_t DeltaTime)
{
	TCHAR temp[10] = { 0 };			
	wcscat_s(OutputBuffer, 60, Output_lable_finishedtext);
	if (DeltaTime < 1000)
	{
		if (DeltaTime == 0)
		{			
			wcscat_s(OutputBuffer, 60, Smaller_Than_One_text);
			return;
		}
		_itow_s(DeltaTime, temp, 10, 10);
		wcscat_s(OutputBuffer, 60, temp);
		wcscat_s(OutputBuffer, 60, Milliseconds_text);
	}
	else
	{	
		uint32_t s = DeltaTime / 1000;
		_itow_s(s, temp, 10, 10);
		wcscat_s(OutputBuffer, 60, temp);		
		wcscat_s(OutputBuffer, 60, L".");
		s = DeltaTime % 1000;
		if (s < 100)
		{
			wcscat_s(OutputBuffer, 60, L"0");
			if (s < 10)
				wcscat_s(OutputBuffer, 60, L"0");
		}
		_itow_s(s, temp, 10, 10);
		wcscat_s(OutputBuffer, 60, temp);
		wcscat_s(OutputBuffer, 60, Seconds_text);
	}	
}

void FormatInfoLableOutput(TCHAR* InfoOutputBuffer, uint32_t bufferlen, ProgressStrcure* p)
{
	TCHAR temp[4] = { 0 };
	InfoOutputBuffer[0] = L'\0';
	if (_tcslen(p->FilenameUnderProcessing) > bufferlen - 30)
	{
		wcscat_s(InfoOutputBuffer, bufferlen, Output_nametoolong_text);
		return;
	}
	wcscat_s(InfoOutputBuffer,  bufferlen, Output_processing_text);
	_itow_s(p->FileUnderProcessing, temp, 4, 10);
	wcscat_s(InfoOutputBuffer, bufferlen, temp);
	wcscat_s(InfoOutputBuffer, bufferlen, L"/");
	_itow_s(p->TotalFileToProcess, temp, 4, 10);
	wcscat_s(InfoOutputBuffer, bufferlen, temp);
	wcscat_s(InfoOutputBuffer, bufferlen, L"): ");
	wcscat_s(InfoOutputBuffer, bufferlen, p->FilenameUnderProcessing);
	wcscat_s(InfoOutputBuffer, bufferlen, L" -> ");
	_itow_s(p->CurrentFilePrecetage, temp, 4, 10);
	wcscat_s(InfoOutputBuffer, bufferlen, temp);
	wcscat_s(InfoOutputBuffer, bufferlen, L"%");
}

void *swap_uint32_memcpy(void *to, const void *from, size_t length)
{
	memcpy(to, from, length);
	size_t remain_len = (4 - (length & 3)) & 3;

	//数据不是4字节的倍数,补充0
	if (remain_len)
	{
		for (size_t i = 0; i < remain_len; ++i)
		{
			*((char *)(to)+length + i) = 0;
		}
		//调整成4的倍数
		length += remain_len;
	}

	//所有的数据反转
	for (size_t i = 0; i < length / 4; ++i)
	{
		((uint32_t *)to)[i] = SWAP_UINT32(((uint32_t *)to)[i]);
	}

	return to;
}

void *swap_uint64_memcpy(void *to, const void *from, size_t length)
{
	memcpy(to, from, length);
	size_t remain_len = (8 - (length & 5)) & 5;

	if (remain_len)
	{
		for (size_t i = 0; i < remain_len; ++i)
		{
			*((char *)(to)+length + i) = 0;
		}
	
		length += remain_len;
	}

	for (size_t i = 0; i < length / 8; ++i)
	{
		((uint64_t *)to)[i] = SWAP_UINT64(((uint64_t *)to)[i]);
	}

	return to;
}



/*!
@brief      求某个文件的HASH
@return     bool 如果顺利结束,返回true,否则(用户点击了stop)返回false
@param[in]  hFile    文件的句柄
@param[in]  FileSize   文件的长度
@param[in]	PGBar 进度条句柄
@param[in]	InfoLable 状态栏句柄
@param[in_out] pb 进度保存结构
@param[out] Result stcture
@param[in] Setting
@param[in] stp 全局bool变量,指示stop按钮是否被点击
*/
bool File_Hash(HANDLE hFile, uint64_t FileSize, HWND PGBar, HWND InfoLable, ProgressStrcure* pb, HASH_ctx* ctx, Settings* s, bool* stp)
{	
	unsigned char ReadBuffer[READ_BUFFER_SIZE];
	TCHAR InfoLableOutputbuffer[90];
	DWORD lp = 0;
	int i = 0;
	uint64_t CurrentBytesProcessed = 0;
	FILETIME OriginalFileT;
	FILETIME LocalFileT;

	GetFileTime(hFile, NULL, NULL, &OriginalFileT);
	ctx->unprocessed_ = FileSize;
	ctx->length_ = FileSize;
	if (s->MD5)
		md5_init_file(ctx, FileSize);
	if (s->MD2)
		md2_init_file(ctx, FileSize);
	if (s->MD4)
		md4_init_file(ctx, FileSize);
	if (s->SHA1)
		sha1_init_file(ctx, FileSize);
	if (s->SHA224)
		sha224_init_file(ctx, FileSize);
	if (s->SHA256)
		sha256_init_file(ctx, FileSize);
	if (s->SHA384)
		sha384_init_file(ctx, FileSize);
	if (s->SHA512)
		sha512_init_file(ctx, FileSize);
	if (s->CRC32)
		ctx->CRC32_hash_ = 0;
	if (s->CRC16)
		ctx->CRC16_hash_ = 0;
	while (ctx->unprocessed_ > READ_BUFFER_SIZE)
	{
		if (*stp)
		{
			SendMessage(PGBar, PBM_SETPOS, 0, 0);
			SendMessage(InfoLable, WM_SETTEXT, NULL, (LPARAM)Info_lable_caption);
			return false;		//Stop button was hit!
		}
		ReadFile(hFile, ReadBuffer, READ_BUFFER_SIZE, &lp, NULL);
		if (s->MD5)
			md5_update_file(ctx, ReadBuffer, READ_BUFFER_SIZE);
		if (s->MD2)
			md2_update_file(ctx, ReadBuffer, READ_BUFFER_SIZE);
		if (s->MD4)
			md4_update_file(ctx, ReadBuffer, READ_BUFFER_SIZE);
		if (s->SHA1)
			sha1_update_file(ctx, ReadBuffer, READ_BUFFER_SIZE);
		if (s->SHA224)
			sha224_update_file(ctx, ReadBuffer, READ_BUFFER_SIZE);
		if (s->SHA256)
			sha256_update_file(ctx, ReadBuffer, READ_BUFFER_SIZE);
		if (s->SHA384)
			sha384_update_file(ctx, ReadBuffer, READ_BUFFER_SIZE);
		if (s->SHA512)
			sha512_update_file(ctx, ReadBuffer, READ_BUFFER_SIZE);
		if (s->CRC32 || s->CRC16)
			CRC_Process(ctx, ReadBuffer, READ_BUFFER_SIZE, s);
		pb->BytesProcessed += READ_BUFFER_SIZE;
		CurrentBytesProcessed += READ_BUFFER_SIZE;
		ctx->unprocessed_ -= READ_BUFFER_SIZE;
		if (pb->BytesProcessed > pb->Checker)
		{
			i = (int)(100 * pb->BytesProcessed / pb->TotalBytesToProcess);
			pb->CurrentFilePrecetage = (uint32_t)(100 * CurrentBytesProcessed / FileSize);
			FormatInfoLableOutput(InfoLableOutputbuffer, 90, pb);
			SendMessage(PGBar, PBM_SETPOS, i, 0);
			SendMessage(InfoLable, WM_SETTEXT, NULL, (LPARAM)InfoLableOutputbuffer);
			pb->Checker += pb->TotalBytesToProcess / 50;
		}

	}
	ReadFile(hFile, ReadBuffer, (size_t)ctx->unprocessed_, &lp, NULL);
	pb->BytesProcessed += READ_BUFFER_SIZE;
	if (s->MD5)
	{
		md5_final_file(ctx, ReadBuffer, (size_t)ctx->unprocessed_);
		uCharToHexStringFormat(ctx->MD5_result, ctx->MD5_HexResult_Output, MD5_HASH_SIZE, MD5_HASH_RESULT_TEXT_SIZE, s->LetterCase);
	}		
	if (s->MD2)
	{
		md2_final_file(ctx, ReadBuffer, (size_t)ctx->unprocessed_);
		uCharToHexStringFormat(ctx->MD2_result, ctx->MD2_HexResult_Output, MD2_HASH_SIZE, MD2_HASH_RESULT_TEXT_SIZE, s->LetterCase);
	}		
	if (s->MD4)
	{
		md4_final_file(ctx, ReadBuffer, (size_t)ctx->unprocessed_);
		uCharToHexStringFormat(ctx->MD4_result, ctx->MD4_HexResult_Output, MD4_HASH_SIZE, MD4_HASH_RESULT_TEXT_SIZE, s->LetterCase);
	}		
	if (s->SHA1)
	{
		sha1_final_file(ctx, ReadBuffer, (size_t)ctx->unprocessed_);
		uCharToHexStringFormat(ctx->SHA1_result, ctx->SHA1_HexResult_Output, SHA1_HASH_SIZE, SHA1_HASH_RESULT_TEXT_SIZE, s->LetterCase);
	}		
	if (s->SHA224)
	{
		sha224_final_file(ctx, ReadBuffer, (size_t)ctx->unprocessed_);
		uCharToHexStringFormat(ctx->SHA224_result, ctx->SHA224_HexResult_Output, SHA224_HASH_SIZE, SHA224_HASH_RESULT_TEXT_SIZE, s->LetterCase);
	}		
	if (s->SHA256)
	{
		sha256_final_file(ctx, ReadBuffer, (size_t)ctx->unprocessed_);
		uCharToHexStringFormat(ctx->SHA256_result, ctx->SHA256_HexResult_Output, SHA256_HASH_SIZE, SHA256_HASH_RESULT_TEXT_SIZE, s->LetterCase);
	}		
	if (s->SHA384)
	{
		sha384_final_file(ctx, ReadBuffer, (size_t)ctx->unprocessed_);
		uCharToHexStringFormat(ctx->SHA384_result, ctx->SHA384_HexResult_Output, SHA384_HASH_SIZE, SHA384_HASH_RESULT_TEXT_SIZE, s->LetterCase);
	}		
	if (s->SHA512)
	{
		sha512_final_file(ctx, ReadBuffer, (size_t)ctx->unprocessed_);
		uCharToHexStringFormat(ctx->SHA512_result, ctx->SHA512_HexResult_Output, SHA512_HASH_SIZE, SHA512_HASH_RESULT_TEXT_SIZE, s->LetterCase);
	}		
	if (s->CRC32 || s->CRC16)
	{
		CRC_Process(ctx, ReadBuffer, (size_t)ctx->unprocessed_, s);
		uIntToHexStringFormat(ctx->CRC32_hash_, ctx->CRC32_HexResult_Output, CRC32_HASH_SIZE, CRC32_HASH_RESULT_TEXT_SIZE, s->LetterCase);
		uIntToHexStringFormat(ctx->CRC16_hash_, ctx->CRC16_HexResult_Output, CRC16_HASH_SIZE, CRC16_HASH_RESULT_TEXT_SIZE, s->LetterCase);
	}		
	FileTimeToLocalFileTime(&OriginalFileT, &LocalFileT);
	FileTimeToSystemTime(&LocalFileT, &ctx->SysFileT);
	return true;
}