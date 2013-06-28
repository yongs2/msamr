/*
mediastreamer2 library - modular sound and video processing and streaming
Copyright (C) 2010  Simon MORLAT
Belledonne Communications SARL, All rights reserved.
simon.morlat@linphone.org

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <mediastreamer2/msfilter.h>
#include "bs.h"
#if defined(ANDROID)
#include <amrnb/interf_dec.h>
#include <amrnb/interf_enc.h>
#else
#include <opencore-amrnb/interf_dec.h>
#include <opencore-amrnb/interf_enc.h>
#endif

#ifdef _MSC_VER
#include <stdint.h>
#endif

/*
                             Class A   total speech
                  Index   Mode       bits       bits
                  ----------------------------------------
                    0     AMR 4.75   42         95
                    1     AMR 5.15   49        103
                    2     AMR 5.9    55        118
                    3     AMR 6.7    58        134
                    4     AMR 7.4    61        148
                    5     AMR 7.95   75        159
                    6     AMR 10.2   65        204
                    7     AMR 12.2   81        244
                    8     AMR SID    39         39
 */

#define MAX_FRAME_TYPE	(8)		// SID Packet
#define OUT_MAX_SIZE	(32)
#define NUM_SAMPLES 	(160)

static const int amr_frame_rates[] = {4750, 5150, 5900, 6700, 7400, 7950, 10200, 12200};

static const int amr_frame_sizes[] = {12, 13, 15, 17, 19, 20, 26, 31, 5, 0 };

typedef struct DecState 
{
	void 			*dec;
	MSBufferizer	*mb;
	uint32_t		ts;
	uint8_t			mode;
	int 			ptime;
	uint8_t			b_octet_align;
} DecState;

static void dec_init(MSFilter *f) 
{
	DecState *s=(DecState *)ms_new(DecState,1);
	s->dec = Decoder_Interface_init();
	s->mb = NULL;
	s->ts = 0;
	s->mode = 0;
	s->ptime = 20;
	s->b_octet_align = 0;
	f->data=s;
}

#define toc_get_f(toc) ((toc) >> 7)
#define toc_get_index(toc)	((toc>>3) & 0xf)

static int toc_list_check(uint8_t *tl, size_t buflen) 
{
	int s = 1;
	while (toc_get_f(*tl))
	{
		tl++;
		s++;
		if (s > buflen)
		{
			return -1;
		}
	}
	return s;
}

static void dec_process(MSFilter *f)
{
	DecState *s=(DecState*)f->data;
	static const int nsamples = NUM_SAMPLES;
	mblk_t *im, *om;
	uint8_t tmp[OUT_MAX_SIZE];
	
	uint8_t	tocs[20] = {0,};
	int 	nTocLen = 0, toclen = 0;
	bs_t	*payload = NULL;
	int		nCmr = 0, nBitLeft = 0, nPadding = 0, nReserved = 0, nRead = 0;
	int		nFbit = 1;
	int		nFTbits = 0;
	int		nQbit = 0;
	int		nFrameData = 0;
	int		nSize = 0, i = 0, index = 0, framesz = 0;
	
	while ((im = ms_queue_get(f->inputs[0])) != NULL)
	{
		nSize = msgdsize(im);
		if (nSize < 2)
		{
			ms_warning("Too short packet");
			freemsg(im);
			continue;
		}
		payload = bs_new(im->b_rptr, nSize);
		if(payload == NULL)
			break;
		
		if(s->b_octet_align == 0)
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
		{	// 0                   1
			// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			// |1|  FT   |Q|1|  FT   |Q|0|  FT   |Q|
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			nFbit = bs_read_u(payload, 1);
			nFTbits = bs_read_u(payload, 4);
			if(nFTbits > MAX_FRAME_TYPE)
			{
				ms_warning("%s, Bad amr toc, index=%i (MAX=%d)", __func__, nFTbits, MAX_FRAME_TYPE);
				break;
			}
			nFrameData += amr_frame_sizes[nFTbits];
			nQbit = bs_read_u(payload, 1);
			tocs[nTocLen++] = ((nFbit << 7) | (nFTbits << 3) | (nQbit << 2)) & 0xFC;
			if(s->b_octet_align == 1)
			{	// octet-align 모드에서는 Padding bit 2bit를 더 읽어야 한다.
				nPadding = bs_read_u(payload, 2);
			}
			//ms_message("%s, F=%d, FT=%d, Q=%d, tocs[%d]=0x%x, FrameData=%d", __func__, nFbit, nFTbits, nQbit, nTocLen, tocs[nTocLen-1], nFrameData);
		} // end of while
		nBitLeft = payload->bits_left;
		
		if(s->b_octet_align == 0)
		{
			//ms_message("%s, nCmr=%d, TOC=%d, nPadding(%d)=%d, FrameData=%d", __func__, nCmr, nTocLen, nBitLeft, nPadding, nFrameData);
		}
		else
		{
			//ms_message("%s, nCmr=%d, nReserved=%d, TOC=%d, nPadding(%d)=%d, FrameData=%d", __func__, nCmr, nReserved, nTocLen, nBitLeft, nPadding, nFrameData);
		}
		
		toclen = toc_list_check(tocs, nSize);
		if (toclen == -1)
		{
			ms_warning("Bad AMR toc list");
			freemsg(im);
			continue;
		}
        
		if((nFrameData) != bs_bytes_left(payload))
		{
			ms_warning("%s, invalid data mismatch, FrameData=%d, bytes_left=%d", __func__, nFrameData, bs_bytes_left(payload));
		}
		for(i=0; i<nTocLen; i++)
		{
			memset(tmp, 0, sizeof(tmp));
			tmp[0] = tocs[i];
			index = toc_get_index(tocs[i]);
			if (index > MAX_FRAME_TYPE)
			{
				ms_warning("Bad amr toc, index=%i", index);
				break;
			}
			framesz = amr_frame_sizes[index];
			nRead = bs_read_bytes_ex(payload, &tmp[1], framesz);
			//ms_message("%s, toc=0x%x, bs_read_bytes_ex(framesz=%d)=%d,tmp[5]{%02x %02x%02x %02x%02x}", __func__, tmp[0], framesz, nRead, tmp[1], tmp[2], tmp[3], tmp[4], tmp[5]);
			om = allocb(nsamples * 2, 0);
			mblk_meta_copy(im, om);
			
			Decoder_Interface_Decode(s->dec, tmp, (short*) om->b_wptr, 0);
			om->b_wptr += nsamples * 2;
			ms_queue_put(f->outputs[0], om);
		} // end of for
		bs_free(payload);
		freemsg(im);
	} // end of while
	return;
}

static void dec_uninit(MSFilter *f)
{
	DecState *s=(DecState*)f->data;
	if (s == NULL)
		return;
	if (s->dec != NULL)
		Decoder_Interface_exit(s->dec);
	ms_free(s);
}

static int dec_add_fmtp(MSFilter *f, void *arg)
{
	DecState *s=(DecState*)f->data;
	const char *fmtp=(const char *)arg;
	char buf[32];
	if(fmtp_get_value(fmtp, "octet-align", buf, sizeof(buf)))
	{
		s->b_octet_align = atoi(buf);
		ms_message("AMR-NB: dec.mode=%s", ((s->b_octet_align == 0) ? "bandwidth-efficient" : "octet-align") );
	}
	return 0;
}

static MSFilterMethod dec_methods[]={
	{	MS_FILTER_ADD_FMTP	, dec_add_fmtp	},
	{	0					, NULL			}
};


#ifdef _MSC_VER

MSFilterDesc amrnb_dec_desc = {
	MS_FILTER_PLUGIN_ID,
	"MSAmrDec",
	"AMR narrowband decode based on OpenCore codec.",
	MS_FILTER_DECODER,
	"AMR",
	1,
	1,
	dec_init,
	NULL,
	dec_process,
	NULL,
	dec_uninit,
	dec_methods,
	0
};

#else

MSFilterDesc amrnb_dec_desc = {
    .id = MS_FILTER_PLUGIN_ID,
    .name = "MSAmrDec",
    .text = "AMR narrowband decode based on OpenCore codec.",
    .category = MS_FILTER_DECODER,
    .enc_fmt = "AMR",
    .ninputs = 1,
    .noutputs = 1,
    .init = dec_init,
    .process = dec_process,
    .uninit = dec_uninit,
	
	.methods = dec_methods
};

#endif

typedef struct EncState 
{
	void *enc;
	MSBufferizer *mb;
	uint32_t ts;
	uint8_t mode;
	int ptime;
	bool_t dtx;
	uint8_t	b_octet_align;
} EncState;

static void enc_init(MSFilter *f) 
{
    EncState *s = ms_new0(EncState, 1);
    s->dtx = FALSE;
    s->mb = ms_bufferizer_new();
    s->ts = 0;
    s->mode = 7;
    s->ptime = 20;
    s->b_octet_align = 0;
    f->data = s;
}

static void enc_uninit(MSFilter *f) 
{
	EncState *s = (EncState*) f->data;
	ms_bufferizer_destroy(s->mb);
	ms_free(s);
}

static void enc_preprocess(MSFilter *f) 
{
	EncState *s = (EncState*) f->data;
	s->enc = Encoder_Interface_init(s->dtx);
}

static void enc_process(MSFilter *f)
{
	EncState *s = (EncState*) f->data;
	unsigned int unitary_buff_size = sizeof (int16_t) * NUM_SAMPLES;
	unsigned int buff_size = unitary_buff_size * s->ptime / 20;
	mblk_t *im;
	uint8_t tmp[OUT_MAX_SIZE];
	int16_t samples[buff_size];
	uint8_t	tmp1[20*OUT_MAX_SIZE];
	bs_t	*payload = NULL;
	int		nCmr = 0xF;
	int		nFbit = 1, nFTbits = 0, nQbit = 0;
	int		nReserved = 0, nPadding = 0;
	int		nFrameData = 0, framesz = 0, nWrite = 0;
	int		offset = 0;
	
	while ((im = ms_queue_get(f->inputs[0])) != NULL)
	{
		ms_bufferizer_put(s->mb, im);
	}
	
	while (ms_bufferizer_get_avail(s->mb) >= buff_size)
	{
		mblk_t *om = allocb(OUT_MAX_SIZE * buff_size / unitary_buff_size + 1, 0);
		ms_bufferizer_read(s->mb, (uint8_t*) samples, buff_size);
		
		payload = bs_new(om->b_wptr, OUT_MAX_SIZE * buff_size / unitary_buff_size + 1);
		if(s->b_octet_align == 0)
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
		
		nFrameData = 0; nWrite = 0;
		for (offset = 0; offset < buff_size; offset += unitary_buff_size)
		{
			int ret = Encoder_Interface_Encode(s->enc, s->mode, &samples[offset / sizeof (int16_t)], tmp, s->dtx);
			if (ret <= 0 || ret > 32)
			{
				ms_warning("Encoder returned %i", ret);
				freemsg(om);
				continue;
			}
			nFbit = tmp[0] >> 7;
			nFbit = (offset+buff_size >= unitary_buff_size) ? 0 : 1;
			nFTbits = tmp[0] >> 3 & 0x0F;
			if(nFTbits > MAX_FRAME_TYPE)
			{
				ms_warning("%s, Bad amr toc, index=%i (MAX=%d)", __func__, nFTbits, MAX_FRAME_TYPE);
				break;
			}
			nQbit = tmp[0] >> 2 & 0x01;
			framesz = amr_frame_sizes[nFTbits];
			//ms_message("%s, %03d(%d,%d), F=%d, FT=%d, Q=%d, framesz=%d (%d),tmp1=%d", __func__, offset, offset+buff_size, unitary_buff_size, nFbit, nFTbits, nQbit, framesz, ret-1, nFrameData);
			
			// Frame 데이터를 임시로 복사
			memcpy(&tmp1[nFrameData], &tmp[1], framesz);
			nFrameData += framesz;
			
			// write TOC
			bs_write_u(payload, 1, nFbit);
			bs_write_u(payload, 4, nFTbits);
			bs_write_u(payload, 1, nQbit);
			if(s->b_octet_align == 1)
			{	// octet-align, add padding bit
				bs_write_u(payload, 2, nPadding);
			}
		} // end of for
		if(offset > 0)
		{
			nWrite = bs_write_bytes_ex(payload, tmp1, nFrameData);
		}
		//ms_message("%s, bs_write_bytes_ex(framesz=%d)=%d(%d),tmp[6]{%02x%02x %02x%02x %02x%02x}", __func__, framesz, nWrite, bs_pos(payload), tmp1[0], tmp1[1], tmp1[2], tmp1[3], tmp1[4], tmp1[5]);
		om->b_wptr += bs_pos(payload);
		
		mblk_set_timestamp_info(om, s->ts);
		ms_queue_put(f->outputs[0], om);
		
		s->ts += buff_size / sizeof (int16_t)/*sizeof(buf)/2*/;
		bs_free(payload);
	} // end of while
}

static void enc_postprocess(MSFilter *f) 
{
	EncState *s = (EncState*) f->data;
	Encoder_Interface_exit(s->enc);
	s->enc = NULL;
	ms_bufferizer_flush(s->mb);
}

static int enc_set_br(MSFilter *f, void *arg) 
{
	EncState *s = (EncState*) f->data;
	int pps = 1000 / s->ptime;
	int ipbitrate = ((int*) arg)[0];
	int cbr = (int) (((((float) ipbitrate) / (pps * 8)) - 20 - 12 - 8) * pps * 8);
	int i;

	ms_message("Setting maxbitrate=%i to AMR-NB encoder.", cbr);
	
	for (i = 0; i < sizeof (amr_frame_rates) / sizeof (amr_frame_rates[0]); i++) 
	{
		if (amr_frame_rates[i] > cbr) 
		{
			break;
		}
	}
	if (--i >= 0) 
	{
		s->mode = i;
		ipbitrate = ((amr_frame_rates[i] / (pps * 8)) + 20 + 12 + 8) * 8 * pps;
		ms_message("Using bitrate %i for AMR-NB encoder, ip bitrate is %i", amr_frame_rates[i], ipbitrate);
	}
	else
	{
		ms_error("Could not set maxbitrate %i to AMR-NB encoder.", ipbitrate);
	}
	return 0;
}

static int enc_get_br(MSFilter *f, void *arg)
{
	EncState *s = (EncState*) f->data;
	((int*) arg)[0] = amr_frame_rates[s->mode];
	return 0;
}

static int enc_add_fmtp(MSFilter *f, void *arg) 
{
	char buf[64];
	const char *fmtp = (const char *) arg;
	EncState *s = (EncState*) f->data;
	
	memset(buf, '\0', sizeof (buf));
	if (fmtp_get_value(fmtp, "ptime", buf, sizeof (buf)))
	{
		s->ptime = atoi(buf);
		//if the ptime is not a mulptiple of 20, go to the next multiple
		if (s->ptime % 20)
			s->ptime = s->ptime - s->ptime % 20 + 20;
		ms_message("AMR-NB: got ptime=%i", s->ptime);
    }
	if (fmtp_get_value(fmtp, "mode", buf, sizeof (buf))) 
	{
		s->mode = atoi(buf);
		if (s->mode < 0) s->mode = 0;
		if (s->mode > 8) s->mode = 8;
		ms_message("AMR-NB: got mode=%i", s->mode);
	}
	if(fmtp_get_value(fmtp, "octet-align", buf, sizeof(buf)))
	{
		s->b_octet_align = atoi(buf);
		ms_message("AMR-NB: enc.mode=%s", ((s->b_octet_align == 0) ? "bandwidth-efficient" : "octet-align") );
	}
	return 0;
}

static int enc_add_attr(MSFilter *f, void *arg) 
{
	const char *fmtp = (const char *) arg;
	EncState *s = (EncState*) f->data;
	
	if (strstr(fmtp, "ptime:10") != NULL) {
		s->ptime = 20;
	} else if (strstr(fmtp, "ptime:20") != NULL) {
		s->ptime = 20;
	} else if (strstr(fmtp, "ptime:30") != NULL) {
		s->ptime = 40;
	} else if (strstr(fmtp, "ptime:40") != NULL) {
		s->ptime = 40;
	} else if (strstr(fmtp, "ptime:50") != NULL) {
		s->ptime = 60;
	} else if (strstr(fmtp, "ptime:60") != NULL) {
		s->ptime = 60;
	} else if (strstr(fmtp, "ptime:70") != NULL) {
		s->ptime = 80;
	} else if (strstr(fmtp, "ptime:80") != NULL) {
		s->ptime = 80;
	} else if (strstr(fmtp, "ptime:90") != NULL) {
		s->ptime = 100; /* not allowed */
	} else if (strstr(fmtp, "ptime:100") != NULL) {
		s->ptime = 100;
	} else if (strstr(fmtp, "ptime:110") != NULL) {
		s->ptime = 120;
	} else if (strstr(fmtp, "ptime:120") != NULL) {
		s->ptime = 120;
	} else if (strstr(fmtp, "ptime:130") != NULL) {
		s->ptime = 140;
	} else if (strstr(fmtp, "ptime:140") != NULL) {
		s->ptime = 140;
	}
	ms_message("AMR-WB: got ptime=%i", s->ptime);
	return 0;
}

static MSFilterMethod enc_methods[] = {
	{ MS_FILTER_SET_BITRATE, enc_set_br},
	{ MS_FILTER_GET_BITRATE, enc_get_br},
	{ MS_FILTER_ADD_FMTP, enc_add_fmtp},
	{ MS_FILTER_ADD_ATTR, enc_add_attr},
	{ 0, NULL}
};

#ifdef _MSC_VER

MSFilterDesc amrnb_enc_desc = {
	MS_FILTER_PLUGIN_ID,
	"MSAmrEnc",
	"AMR encoder based OpenCore codec",
	MS_FILTER_ENCODER,
	"AMR",
	1,
	1,
	enc_init,
	enc_preprocess,
	enc_process,
	enc_postprocess,
	enc_uninit,
	enc_methods,
	0
};

#else

MSFilterDesc amrnb_enc_desc = {
	.id = MS_FILTER_PLUGIN_ID,
	.name = "MSAmrEnc",
	.text = "AMR encoder based OpenCore codec",
	.category = MS_FILTER_ENCODER,
	.enc_fmt = "AMR",
	.ninputs = 1,
	.noutputs = 1,
	.init = enc_init,
	.preprocess = enc_preprocess,
	.process = enc_process,
	.postprocess = enc_postprocess,
	.uninit = enc_uninit,
	.methods = enc_methods
};

#endif
