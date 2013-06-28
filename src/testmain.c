#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include "bs.h"
#include <time.h>

// 시간 측정 함수 소스
void stopWatch()
{
	static struct timeval start, end, elapsed;
	static int bCheckTime = 0;
	static int timerCount = 0;

	if( !bCheckTime )
	{
		gettimeofday(&start, NULL);
		timerCount++;
	}
	if( bCheckTime )
	{
		gettimeofday(&end, NULL);
		elapsed.tv_sec = end.tv_sec - start.tv_sec;
		elapsed.tv_usec = end.tv_usec - start.tv_usec;
		printf("%s, .............................Time %d : %ld.%06ld sec\n", __func__, timerCount, elapsed.tv_sec, elapsed.tv_usec);
	}

	bCheckTime = (bCheckTime == 0) ? 1 : 0;
} 

static int DumpData(char *cData, int nLenth, char *cFormat, ...)
{
	int 	nCol = 16;
	int		i, column;
	char	ascii_buf[128], *ptrT;
	char	hex_buf[128], *hexp;
	int		nSum = 0;
	int		nRet;
	FILE	*_log_fp = stdout;
	FILE	*fp = stdout;
	va_list 	ap;
	
	va_start (ap, cFormat);
	nRet = vfprintf(fp, cFormat, ap);
	va_end (ap);
		
	ptrT = (char *)cData;
	hexp = hex_buf;
	for (i = 0; i < nLenth; i++) {
		column = i % nCol;

		/* print the number of low before the first columm */
		if (column == 0) {
			if( (nRet=fprintf(fp, "0x%04X | ", i)) > 0 ) {
				nSum += nRet;
			}
		}

		/* print hexa code value */
		if( (nRet=fprintf (_log_fp, "%02X ", (unsigned char)ptrT[i] & 0xFF)) > 0 ) {
			nSum += nRet;
		}

		/* gether ascii value */
		if(ptrT[i] == 0) {
			ascii_buf[column] = '.';
		} else {
			ascii_buf[column] = isprint((int)ptrT[i]) ? ptrT[i] : '_';
		}

        /* print ascii value */
        if (column==(nCol-1)) {
            ascii_buf[column+1] = 0;
            if( (nRet=fprintf (_log_fp, "| %s\n", ascii_buf)) > 0 ) {
				nSum += nRet;
			}
        } else if (i == (nLenth-1)) {
            ascii_buf[column+1] = 0;
            if( (nRet=fprintf (_log_fp, "%*s| %s\n", 3*(nCol-column-1), "", ascii_buf)) > 0 ) {
				nSum += nRet;
			}
        }
    }
	return i;
}

uint8_t* bs_startp(bs_t *b)
{
	return b->start;
}

int bs_size(bs_t *b)
{
	int actual_len = 0;
	actual_len = b->end - b->start;
    if (actual_len < 0) { actual_len = 0; }
    return actual_len;
}

#if 0 	// 기존 bs.h 에 적용된 소스 - 참고용
static inline int bs_read_bytes_ex(bs_t* b, uint8_t* buf, int len)
{
    int actual_len = len, nReadLen = 0, i=0;
    uint8_t nUpper = 0, nLower = 0;		// nOrg = 0;
    uint8_t nReadUpper = 0, nReadLower = 0;
    
    if(b->bits_left == 8)
    {
        return bs_read_bytes(b, buf, len);
    }
    else
    {
        if (b->end - b->p < actual_len) { actual_len = b->end - b->p; }
        if (actual_len < 0) { actual_len = 0; }
        
        //printf("%s, actual_len=%d\n", __func__, actual_len);
        nReadLen = 0;
        for(i=0; i<actual_len; i++)
        {
            nUpper = 0; nLower = 0;
            //nOrg = *(b->p);
            nReadUpper = b->bits_left;
            nReadLower = 8 - b->bits_left;
            nUpper = bs_read_u(b, nReadUpper);
            nLower = bs_read_u(b, nReadLower);
            *buf = (nUpper << nReadLower) | (nLower);
            //printf("%s, [%02d] Org=[0x%02x] R[%d,%d]=[0x%02x,0x%02x]=0x%02x\n", __func__, i, nOrg, nReadUpper, nReadLower, nUpper, nLower, *buf);
            buf++;
            nReadLen++;
            if(nReadLen > len)
                break;
        } // end of for
        return nReadLen;
    }
}

static inline int bs_write_bytes_ex(bs_t* b, uint8_t* buf, int len)
{
	int actual_len = len, nWriteLen = 0, i=0;
	uint8_t	nUpper = 0, nLower = 0, nOrg = 0;
	uint8_t nReadUpper = 0, nReadLower = 0;
	
	if(b->bits_left == 8)
	{
		return bs_write_bytes(b, buf, len);
	}
	else
	{
		if (b->end - b->p < actual_len) { actual_len = b->end - b->p; }
		if (actual_len < 0) { actual_len = 0; }
		
		//printf("%s, actual_len=%d\n", __func__, actual_len);
		nWriteLen = 0;
		for(i=0; i<actual_len; i++)
		{
			nUpper = 0; nLower = 0;
			// b->bits_left=3, ReadUpper=3, ReadLower=5
			//nOrg = *buf;
			nReadUpper = b->bits_left;
			nReadLower = 8 - b->bits_left;
			nUpper = *buf >> ( nReadLower);
			nLower = *buf & (0xFF >> nReadUpper);
			bs_write_u(b, nReadUpper, nUpper);
			bs_write_u(b, nReadLower, nLower);
			//printf("%s, [%02d] Org=[0x%02x] R[%d,%d(%d)]=[0x%02x,0x%02x]=0x%02x\n", __func__, i, nOrg, nReadUpper, nReadLower, 2 ^ nReadLower, nUpper, nLower, *(b->p-1));
			buf++;
			nWriteLen++;
			if(nWriteLen > len)
				break;
		} // end of for
		if((b->bits_left > 0) && (b->bits_left < 8))
		{	// bits_left 가 있다면, 0x00 을 붙여서 처리하여야 한다.
			nOrg = 0;
			nReadUpper = b->bits_left;
			nReadLower = 8 - b->bits_left;
			nUpper = nOrg >> ( nReadLower);
			nLower = nOrg & (0xFF >> nReadUpper);
			bs_write_u(b, nReadUpper, nUpper);
			bs_write_u(b, nReadLower, nLower);
			//printf("%s, [%02d] Org=[0x%02x] R[%d,%d(%d)]=[0x%02x,0x%02x]=0x%02x,left=%d\n", __func__, i, nOrg, nReadUpper, nReadLower, 0xFF >> nReadUpper, nUpper, nLower, *(b->p-1), b->bits_left);
		}
		return nWriteLen;
	}
}
#else
int bs_read_bytes_ex2(bs_t* b, uint8_t* buf, int len)
{
	int i=0, mask = 0xFF, shift = 0;
	int value = 0, remain = 0;

	if(b->bits_left == 8)
	{
		return bs_read_bytes(b, buf, len);
	}
	
	for(i=0; i<len; i++)
	{
		if(bs_eof(b)) break;

		remain = b->bits_left;		// 6비트가 남아 있다.
		shift = (8 - b->bits_left);	// 6비트를 처리하므로, 나머지는 2 bits 이다.

		// Get value from b (1st)
		mask = 0xFF >> shift;		// 6비트를 추출하려면 2bits만 이동한다.
		//printf("[%02d] *buf[0x%02x] v[0x%02x] m[0x%02x] 1..b[0x%02x]\n", i, *buf, value, mask, *(b->p));
		
		value = *(b->p) & mask;
		*buf |= (value << shift);	// 6비트를 설정했으므로, 2bits를 이동해야 한다.
		//printf("[%02d] *buf[0x%02x] v[0x%02x] m[0x%02x] 2..b[0x%02x]\n", i, *buf, value, mask, *(b->p));

		b->p ++; b->bits_left = 8;	// Next bit
		if(bs_eof(b))
		{	// 더 이상 읽을 데이터가 없으므로 여기서 마무리 한다.
			i++;	// buf에 상위 비트를 설정했으므로, 길이를 증가시킨 후 종료한다.
			break;
		}

		// Get value from b (2nd)
		mask = 0xFF >> remain;		// 2bits 를 추출하려면 6 bits 이동한다.
		value = *(b->p) >> (remain);// 2bits 를 추츨하려면 6 bits 이동한다.
		b->bits_left = remain;		// 2 bits를 추출하므로, 6 bits 남아 있음.
		*buf |= value & mask;

		//printf("[%02d] *buf[0x%02x] v[0x%02x] m[0x%02x] 3..b[0x%02x]\n", i, *buf, value, mask, *(b->p));
		buf++;
	} // end of for
	return i;
}

int bs_write_bytes_ex2(bs_t* b, uint8_t* buf, int len)
{
	int i=0, mask = 0xFF, shift = 0;
	int value = 0, remain = 0;

	if(b->bits_left == 8)
	{
		return bs_write_bytes(b, buf, len);
	}
	
	for(i=0; i<len; i++)
	{
		if ( bs_eof(b))	break;

		mask = 0xFF >> b->bits_left;
		shift = (8-b->bits_left);
		// Get value from buffer
		value = *buf >> shift;
		remain = *buf & mask;
		//printf("[%02d] *buf[0x%02x] v[0x%02x] r[0x%02x] 1..b[0x%02x]\n", i, *buf, value, remain, *(b->p));

		// Write value (1st)
		(*(b->p)) |= (value);
		//printf("[%02d] *buf[0x%02x] v[0x%02x] r[0x%02x] 2..b[0x%02x]\n", i, *buf, value, remain, *(b->p));
		b->p ++; b->bits_left = 8;

		// Write remain (2nd)
		b->bits_left = 8-shift;
		(*(b->p)) = 0x00;
		(*(b->p)) |= (remain << (b->bits_left));
		//printf("[%02d] *buf[0x%02x] v[0x%02x] r[0x%02x] 3..b[0x%02x]\n", i, *buf, value, remain, *(b->p));
		
		buf++;
	} // end of for
	return i;
}
#endif

int char2byte(char *pszData, int nLen, uint8_t *pOut)
{
	int		n=0, i=0;
	char	szTemp[10];
	uint8_t	cVal = 0;
	
	n = 0;
	for(i=0; i<nLen; i+=2)
	{
		szTemp[0] = pszData[i];
		szTemp[1] = pszData[i+1];
		szTemp[2] = '\0';
		cVal = (uint8_t)(strtol(szTemp, (char **)NULL, 16));
		pOut[n++] = cVal;
	}
	return n;
}

static const int amr_frame_sizes[] = {
	12,
	13,
	15,
	17,
	19,
	20,
	26,
	31,
	5,
	0
};

#define MAX_FRAME		(10)
#define MAX_FRAME_TYPE	(8)		// SID Packet
#define OUT_MAX_SIZE 32
#define toc_get_f(toc) ((toc) >> 7)
#define toc_get_index(toc)	((toc>>3) & 0xf)

static int toc_list_check(uint8_t *tl, size_t buflen)
{
	int s = 1;
	while (toc_get_f(*tl)) {
		tl++;
		s++;
		if (s > buflen) {
			return -1;
		}
	}
	return s;
}

int ReadPayload(bs_t *payload, int b_octet_align)
{
	uint8_t tmp[OUT_MAX_SIZE];
	
	uint8_t	tocs[20] = {0,};
	int 	nTocLen = 0, toclen = 0;
	int		nCmr = 0;
	int		nFbit = 1;
	int		nFTbits = 0;
	int		nQbit = 0;
	int		nReserved = 0, nPadding = 0, nBitLeft = 0, nBitLeft1 = 0;
	int		nFrameData = 0;
	int		nSize = 0, i = 0, index = 0, framesz = 0, nRead = 0;

	if(b_octet_align == 0)
	{	// Bandwidth efficient mode
		// 1111 ; CMR (4 bits)
		nCmr = bs_read_u(payload, 4);
	}
	else
	{	// octet-aligned mode
		// 1111 0000 ; CMR (4 bits), Reserved (4 bits)
		nCmr = bs_read_u(payload, 4);
		nReserved = bs_read_u(payload, 4);
	}
	
	nTocLen = 0; nFrameData = 0;
	while(nFbit == 1)
	{
		// 0				   1
		// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |1|  FT   |Q|1|  FT   |Q|0|  FT   |Q|
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		
		// *  A ToC entry takes the following format in octet-aligned mode: 항상 padding 붙는다.
		// *
		// *    0 1 2 3 4 5 6 7
		// *   +-+-+-+-+-+-+-+-+
		// *   |F|  FT   |Q|P|P|
		// *   +-+-+-+-+-+-+-+-+
		nFbit = bs_read_u(payload, 1);
		nFTbits = bs_read_u(payload, 4);
		if(nFTbits > MAX_FRAME_TYPE)
		{
			printf("%s, Bad amr toc, index=%i (MAX=%d)\n", __func__, nFTbits, MAX_FRAME_TYPE);
			break;
		}
		nFrameData += amr_frame_sizes[nFTbits];
		nQbit = bs_read_u(payload, 1);
		tocs[nTocLen++] = ((nFbit << 7) | (nFTbits << 3) | (nQbit << 2)) & 0xFC;
		if(b_octet_align == 1)
		{	// octet-align 모드에서는 Padding bit 2bit를 더 읽어야 한다.
			nPadding = bs_read_u(payload, 2);
		}
		printf("%s, F=%d, FT=%d, Q=%d, tocs[%d]=0x%x, FrameData=%d\n", __func__, nFbit, nFTbits, nQbit, nTocLen, tocs[nTocLen-1], nFrameData);
	} // end of while
	nBitLeft = payload->bits_left;
	
	if(b_octet_align == 0)
	{	// be 모드에서는 header 다음에 padding 2 bytes 없이 바로 AMR 데이터가 와야 한다. 데이터 마지막에만 padding 이 붙는다.
		printf("%s, nCmr=%d, TOC=%d, nPadding(%d)=%d, FrameData=%d\n", __func__, nCmr, nTocLen, nBitLeft, nPadding, nFrameData);
	}
	else
	{	// oa 모드에서는 header 다음에 padding 2 bytes가 항상 있음.
		printf("%s, nCmr=%d, nReserved=%d, TOC=%d, nPadding(%d)=%d, FrameData=%d\n", __func__, nCmr, nReserved, nTocLen, nBitLeft, nPadding, nFrameData);
	}
	
	toclen = toc_list_check(tocs, nSize);
	if (toclen == -1)
	{
		printf("Bad AMR toc list");
		return 0;
	}
	
	if((nFrameData) != bs_bytes_left(payload))
	{
		printf("%s, invalid data mismatch, FrameData=%d, bytes_left=%d\n", __func__, nFrameData, bs_bytes_left(payload));
	}
	stopWatch();
	for(i=0; i<nTocLen; i++)
	{
		memset(tmp, 0, sizeof(tmp));
		tmp[0] = tocs[i];
		index = toc_get_index(tocs[i]);
		if (index > MAX_FRAME_TYPE)
		{
			printf("Bad amr toc, index=%i\n", index);
			break;
		}
		framesz = amr_frame_sizes[index];
		nRead = bs_read_bytes_ex2(payload, &tmp[1], framesz);
		//DumpData(tmp, nRead+1, "%s, PKT size=%d, Read=%d...\n", __func__, framesz, nRead);
	}
	stopWatch();

	return 0;
}

int ParsingAmr(char *pszData, int nMode)
{
	uint8_t cHex[128];
	int		nHexSize = 0;
	bs_t	*payload = NULL;
	
	nHexSize = char2byte(pszData, strlen(pszData), cHex);
	if(nHexSize <= 0)
		return;
	
	DumpData(cHex, nHexSize, "%s, PKT size=%d...\n", __func__, nHexSize);
	payload = bs_new(cHex, nHexSize);
	if(payload == NULL)
		return;
	
	ReadPayload(payload, nMode);
	
	bs_free(payload);
	return 0;
}

int WritePayload(bs_t *payload, int b_octet_align, uint8_t	*pcInput, int nInputSize)
{
	uint8_t tmp[MAX_FRAME*OUT_MAX_SIZE];
	
	uint8_t	tocs[20] = {0,};
	int 	nTocLen = 0, toclen = 0;
	int		nCmr = 0xF;
	int		nFbit = 1;
	int		nFTbits = 0;
	int		nQbit = 0;
	int		nReserved = 0, nPadding = 0, nBitLeft = 0, nBitLeft1 = 0;
	int		nFrameData = 0;
	int		nSize = 0, i = 0, index = 0, framesz = 0, nRead = 0;
	
	if(b_octet_align == 0)
	{	// Bandwidth efficient mode
		// 1111 ; CMR (4 bits)
		bs_write_u(payload, 4, nCmr);
	}
	else
	{	// octet-aligned mode
		// 1111 0000 ; CMR (4 bits), Reserved (4 bits)
		bs_write_u(payload, 4, nCmr);
		bs_write_u(payload, 4, nReserved);
	}
	DumpData(bs_startp(payload), bs_pos(payload), "%s, Header...\n", __func__);
	
	for(i=0; i<nInputSize; )
	{
		nFbit = pcInput[i] >> 7;
		nFTbits = pcInput[i] >> 3 & 0x0F;
		if(nFTbits > MAX_FRAME_TYPE)
		{
			printf("%s, Bad amr toc, index=%i (MAX=%d)\n", __func__, nFTbits, MAX_FRAME_TYPE);
			break;
		}
		nQbit = pcInput[i] >> 2 & 0x01;
		framesz = amr_frame_sizes[nFTbits];
		printf("%s, i=%03d, F=%d, FT=%d, Q=%d, framesz=%d\n", __func__, i, nFbit, nFTbits, nQbit, framesz);
		i++;
		
		// Frame 데이터를 임시로 복사
		memcpy(&tmp[nFrameData], &pcInput[i], framesz);
		nFrameData += framesz;
		
		if(b_octet_align == 0)
		{
			bs_write_u(payload, 1, nFbit);
			bs_write_u(payload, 4, nFTbits);
			bs_write_u(payload, 1, nQbit);
			DumpData(bs_startp(payload), bs_pos(payload)+1, "%s, TOC...\n", __func__);
		}
		else
		{	// octet-align
			bs_write_u(payload, 1, nFbit);
			bs_write_u(payload, 4, nFTbits);
			bs_write_u(payload, 1, nQbit);
			bs_write_u(payload, 2, nPadding);
			DumpData(bs_startp(payload), bs_pos(payload), "%s, TOC...\n", __func__);
		}
		i += framesz;
	} // end of for
	
	stopWatch();
	if(i > 0)
	{
		bs_write_bytes_ex2(payload, tmp, nFrameData);
		//DumpData(bs_startp(payload), bs_pos(payload), "%s, PKT size=%d, pos=%d...\n", __func__, bs_size(payload), bs_pos(payload));
	}
	stopWatch();
	
	return 0;
}

int EncodingAmr(char *pszData, int nMode)
{
	uint8_t cHex[1500];		// RTP payload max size
	int	 	nHexSize = 0;
	bs_t	*payload = NULL;
	uint8_t	cOutput[1500];
	
	memset(cOutput, 0, sizeof(cOutput));
	memset(cHex, 0, sizeof(cHex));
	nHexSize = char2byte(pszData, strlen(pszData), cHex);
	if(nHexSize <= 0)
		return;
	
	payload = bs_new(cOutput, nHexSize+10);
	if(payload == NULL)
		return;
	
	WritePayload(payload, nMode, cHex, nHexSize);
	printf("%s, bs_len=%d\n", __func__, bs_pos(payload));
	
	
	bs_free(payload);
	return 0;
}

int main()
{
	char	szAmrData[]= "3c08556d944c71a1a081e7ead204244480000ecd82b81118000097c4794e7740";
	int		nLen = 0;
	char	szBeData[] = "F3C2155B65131C68682079FAB4810911200003B360AE0446000025F11E539DD0";
	char	szOaData[] = "F03c08556d944c71a1a081e7ead204244480000ecd82b81118000097c4794e7740";
	
	nLen = strlen(szAmrData);
	
	printf("-------------------------Decoding BE\n");
	ParsingAmr(szBeData, 0);
	
	memset(szOaData, 0, sizeof(szOaData));
	memcpy(&szOaData[0], "F0", 2);	// CMR, Reserved
	memcpy(&szOaData[2], szAmrData, nLen);
	printf("-------------------------Decoding OA\n");
	ParsingAmr(szOaData, 1);
	
	printf("-------------------------Encoding BE\n");
	EncodingAmr(szAmrData, 0);
	
	printf("-------------------------Encoding OA\n");
	EncodingAmr(szAmrData, 1);
	
	return 0;
}
