/************************************************************************
 * Add Hexdump tool support. This is very useful sometimes when doing 
 * memory data or flash data debuging.
 * Added by Jerome Wang. 2014-11-19.
 *
 * 
 **/

extern void printf (const char *fmt, ...);

static inline int isprint(int c)
{
	return c >= 0x20 && c <= 0x7e;
}

void hexdump(const unsigned char *buff, int length, int offset)
{
    int i = 0;
    int c = 0;
    unsigned char ascii[16*sizeof(unsigned char)+1]; 

    for (i = 0; i < length/16; i++)
    {   
        for (c = 0; c < 16; c++)
        {
            if (!c)
            {
                printf("%08lx  ", offset + i*16 + c);
            }
   
            *(ascii+c) = isprint(*(buff+i*16+c)) ? *(buff+i*16+c) : '.';
            printf("%02x%s", (unsigned int)*(buff+i*16+c), (c+1==16/2)?"  ":" ");

            if (c == 15)
            {
                ascii[16*sizeof(unsigned char)] = '\0';
                printf(" |%s|\n", ascii);
            }
        }
    }
    memset(ascii, '.', 16*sizeof(unsigned char)+1);
    for (c = 0; c < length%16; c++)
    {
        if (!c) printf("%08lx  ", offset + length - length % 16);
        *(ascii+c)   = isprint(*(buff+length-length%16+c)) ? *(buff+length-length%16+c) : '.';
        *(ascii+16*sizeof(unsigned char)) = '\0';
        printf("%02x%s", (unsigned int)*(buff+length-length%16+c), (i+1==16/2)?"  ":" ");
        if (c == (length%16)-1)
        {
            for (i = 0; i < 16-c-1; i++) printf("   ");
            if (c >= 7) printf(" ");
            printf(" |%s|\n", ascii);
        }

    }

	return;
}

