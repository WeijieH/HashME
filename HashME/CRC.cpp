#include "CRC.h"
// CRC16, CRC32
// Reference: http://create.stephan-brumme.com/crc32/

void CRC_Process(HASH_ctx* ctx, unsigned char* buffer, uint32_t size, Settings* s)
{
    if (s->CRC16)
    {
        uint16_t a = ctx->CRC16_hash_;
        for (uint32_t i = 0; i < size; i++)
        {
            a = CRC16_Table[(a ^ buffer[i]) & 0xff] ^ (a >> 8);
        }
        ctx->CRC16_hash_ = a;
    }
    if (s->CRC32)
    {
        uint32_t* current = (uint32_t*)buffer;
        uint32_t length = size;
        uint32_t b = ~ctx->CRC32_hash_;
        while (length >= 8)
        {
            uint32_t one = *current++ ^ b;
            uint32_t two = *current++;
            b = CRC32_Table[7][one & 0xFF] ^ CRC32_Table[6][(one >> 8) & 0xFF] ^ CRC32_Table[5][(one >> 16) & 0xFF] ^ CRC32_Table[4][one >> 24] ^
                CRC32_Table[3][two & 0xFF] ^ CRC32_Table[2][(two >> 8) & 0xFF] ^ CRC32_Table[1][(two >> 16) & 0xFF] ^ CRC32_Table[0][two >> 24];
            length -= 8;
        }
        unsigned char* currentChar = (unsigned char*)current;
        // remaining 1 to 7 bytes
        while (length--)
            b = (b >> 8) ^ CRC32_Table[0][(b & 0xFF) ^ *currentChar++];
        ctx->CRC32_hash_ = ~b;
    }
}

void CRC_Mem(unsigned char* buffer, uint32_t size, Settings* s, HASH_ctx* ctx)
{
    if (s->CRC16)
    {
        ctx->CRC16_hash_ = 0;
    }
    if (s->CRC32)
    {
        ctx->CRC32_hash_ = 0;
    }
    CRC_Process(ctx, buffer, size, s);
}
