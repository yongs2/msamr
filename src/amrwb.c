/*
mediastreamer2 library - modular sound and video processing and streaming
Copyright (C) 2010  Yann DIORCET
Belledonne Communications SARL, All rights reserved.
yann.diorcet@belledonne-communications.com

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

#include "mediastreamer2/msfilter.h"
#include "mediastreamer2/mscodecutils.h"
#include "mediastreamer2/msticker.h"
#include "bs.h"
#if defined(ANDROID)
#include <amrwb/dec_if.h>
#include <enc_if.h>
#else
#include <opencore-amrwb/dec_if.h>
#include <vo-amrwbenc/enc_if.h>
#endif

#ifdef _MSC_VER
#include <stdint.h>
#endif

#define MAX_FRAME_TYPE	(9)		// SID Packet
#define SPEECH_LOST 	(14)
#define OUT_MAX_SIZE 	(61)
#define NUM_SAMPLES 	(320)

static const int amr_frame_rates[] = {6600, 8850, 12650, 14250, 15850, 18250, 19850, 23050, 23850};

/* From pvamrwbdecoder_api.h, by dividing by 8 and rounding up */
static const int amr_frame_sizes[] = {17, 23, 32, 36, 40, 46, 50, 58, 60, 5};

typedef struct DecState 
{
	void				*state;
	MSConcealerContext 	*concealer;
	uint32_t			ts;
	uint8_t				mode;
	int 				ptime;
	uint8_t				b_octet_align;
} DecState;

static void dec_init(MSFilter *f) 
{
	DecState *s = (DecState *) ms_new(DecState, 1);
	s->state = D_IF_init();
	s->concealer = ms_concealer_context_new(UINT32_MAX);
	s->ts = 0;
	s->mode = 0;
	s->ptime = 20;
	s->b_octet_align = 0;
	f->data = s;
}

#define toc_get_f(toc) ((toc) >> 7)
#define toc_get_index(toc) ((toc>>3) & 0xf)

static void decode(MSFilter *f, mblk_t *im);

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
	mblk_t *im;
	
	while ((im = ms_queue_get(f->inputs[0])) != NULL) 
	{
		decode(f, im);
	}
	
	// PLC
	DecState *s = (DecState *) f->data;
	if (ms_concealer_context_is_concealement_required(s->concealer, f->ticker->time))
	{
		decode(f, NULL); /*ig fec_im == NULL, plc*/
	}
}

static void decode(MSFilter *f, mblk_t *im)
{
	DecState *s=(DecState*)f->data;
	static const int nsamples = NUM_SAMPLES;
	mblk_t	*om = NULL;
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
	
	if (im != NULL)
	{
		nSize = msgdsize(im);
		if (nSize < 2)
		{
			ms_warning("Too short packet");
			freemsg(im);
			return;
		}
		
		payload = bs_new(im->b_rptr, nSize);
		if(payload == NULL)
		{
			freemsg(im);
			return;
		}
		
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
			bs_free(payload);
			freemsg(im);
			return;
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
			
            D_IF_decode(s->state, tmp, (int16_t*) om->b_wptr, _good_frame);
			om->b_wptr += nsamples * 2;
			ms_queue_put(f->outputs[0], om);
			
			ms_concealer_inc_sample_time(s->concealer, f->ticker->time, s->ptime, TRUE);
		} // end of for
		bs_free(payload);
		freemsg(im);
	}
	else
	{	//PLC
		tmp[0] = SPEECH_LOST << 3;
		om = allocb(nsamples * 2, 0);
		D_IF_decode(s->state, tmp, (int16_t*) om->b_wptr, 0);
		om->b_wptr += nsamples * 2;
		mblk_set_plc_flag(om, 1);
		ms_queue_put(f->outputs[0], om);
		ms_concealer_inc_sample_time(s->concealer, f->ticker->time, s->ptime, FALSE);
	}
	return;
}

static void dec_uninit(MSFilter *f) 
{
	DecState *s = (DecState*) f->data;
	if (s == NULL)
		return;
	D_IF_exit(s->state);
	ms_concealer_context_destroy(s->concealer);
	ms_free(s);
}

static int dec_have_plc(MSFilter *f, void *arg)
{
	*((int *)arg) = 1;
	return 0;
}

static int dec_add_fmtp(MSFilter *f, void *arg)
{
	DecState *s=(DecState*)f->data;
	const char *fmtp=(const char *)arg;
	char buf[32];
	if(fmtp_get_value(fmtp, "octet-align", buf, sizeof(buf)))
	{
		s->b_octet_align = atoi(buf);
		ms_message("AMR-WB: dec.mode=%s", ((s->b_octet_align == 0) ? "bandwidth-efficient" : "octet-align") );
	}
	return 0;
}

static MSFilterMethod dec_methods[]={
	{	MS_FILTER_ADD_FMTP	, dec_add_fmtp	},
	{ 	MS_DECODER_HAVE_PLC	, dec_have_plc	},
	{	0					, NULL			}
};

#ifdef _MSC_VER

MSFilterDesc amrwb_dec_desc = {
	MS_FILTER_PLUGIN_ID,
	"MSAMRWBDec",
	"AMR Wideband decoder",
	MS_FILTER_DECODER,
	"AMR-WB",
	1,
	1,
	dec_init,
	NULL,
	dec_process,
	NULL,
	dec_uninit,
	dec_methods,
	MS_FILTER_IS_PUMP
};

#else

MSFilterDesc amrwb_dec_desc = {
	.id = MS_FILTER_PLUGIN_ID,
	.name = "MSAMRWBDec",
	.text = "AMR Wideband decoder",
	.category = MS_FILTER_DECODER,
	.enc_fmt = "AMR-WB",
	.ninputs = 1,
	.noutputs = 1,
	.init = dec_init,
	.process = dec_process,
	.uninit = dec_uninit,
	.flags = MS_FILTER_IS_PUMP,
	.methods = dec_methods
};

#endif

typedef struct EncState 
{
	void* state;
	MSBufferizer *bufferizer;
	uint32_t ts;
	uint8_t mode;
	int ptime;
	int dtx;
	uint8_t	b_octet_align;
} EncState;

static void enc_init(MSFilter *f) 
{
    EncState *s = (EncState *) ms_new(EncState, 1);
    s->state = E_IF_init();
	s->bufferizer = ms_bufferizer_new();
    s->ts = 0;
    s->dtx = 0;
    s->mode = 8;
    s->ptime = 20;
    s->b_octet_align = 0;
    f->data = s;
}

static void enc_uninit(MSFilter *f) 
{
	EncState *s = (EncState*) f->data;
	E_IF_exit(s->state);
	ms_bufferizer_destroy(s->bufferizer);
	ms_free(s);
}

static void enc_process(MSFilter *f) 
{
	EncState *s = (EncState*) f->data;
	unsigned int unitary_buff_size = sizeof(int16_t) * NUM_SAMPLES;
	unsigned int buff_size = unitary_buff_size * s->ptime / 20;
	mblk_t *im;
	uint8_t tmp[OUT_MAX_SIZE];
	int16_t buff[buff_size];
	uint8_t	tmp1[20*OUT_MAX_SIZE];
	bs_t	*payload = NULL;
	int		nCmr = 0xF;
	int		nFbit = 1, nFTbits = 0, nQbit = 0;
	int		nReserved = 0, nPadding = 0;
	int		nFrameData = 0, framesz = 0, nWrite = 0;
	int		offset = 0, nAllocSize = 0;
	
	while ((im = ms_queue_get(f->inputs[0])) != NULL)
	{
		ms_bufferizer_put(s->bufferizer, im);
	}
	
	while (ms_bufferizer_get_avail(s->bufferizer) >= buff_size)
	{
		nAllocSize = OUT_MAX_SIZE * buff_size / unitary_buff_size + 1;

		mblk_t *om = allocb(nAllocSize, 0);
		ms_bufferizer_read(s->bufferizer, (uint8_t*) buff, buff_size);
		
		memset(om->b_wptr, 0, nAllocSize);
		payload = bs_new(om->b_wptr, nAllocSize);
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
			int ret = E_IF_encode(s->state, s->mode, &buff[offset/sizeof(int16_t)], tmp, s->dtx);
			if (ret < 1)
			{
				ms_warning("Encoder returned %i (< 1)", ret);
				freemsg(om);
				return;
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

static int enc_set_br(MSFilter *f, void *arg) 
{
	EncState *s = (EncState*) f->data;
	int pps = 1000 / s->ptime;
	int ipbitrate = ((int*) arg)[0];
	int cbr = (int) (((((float) ipbitrate) / (pps * 8)) - 20 - 12 - 8) * pps * 8);
	int i;

	ms_message("Setting maxbitrate=%i to AMR-WB encoder.", cbr);
	
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
		ipbitrate = ((amr_frame_rates[i] / (pps * 8)) + 20 + 12 + 8)*8 * pps;
		ms_message("Using bitrate %i for AMR-WB encoder, ip bitrate is %i", amr_frame_rates[i], ipbitrate);
	}
	else
	{
		ms_error("Could not set maxbitrate %i to AMR-WB encoder.", ipbitrate);
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
		ms_message("AMR-WB: got ptime=%i", s->ptime);
	}
	if (fmtp_get_value(fmtp, "mode", buf, sizeof (buf))) 
	{
		s->mode = atoi(buf);
		if (s->mode < 0) s->mode = 0;
		if (s->mode > 8) s->mode = 8;
		ms_message("AMR-WB: got mode=%i", s->mode);
	}
	if(fmtp_get_value(fmtp, "octet-align", buf, sizeof(buf)))
	{
		s->b_octet_align = atoi(buf);
		ms_message("AMR-WB: enc.mode=%s", ((s->b_octet_align == 0) ? "bandwidth-efficient" : "octet-align") );
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

MSFilterDesc amrwb_enc_desc = {
	MS_FILTER_PLUGIN_ID,
	"MSAMRWBEnc",
	"AMR Wideband encoder",
	MS_FILTER_ENCODER,
	"AMR-WB",
	1,
	1,
	enc_init,
	NULL,
	enc_process,
	NULL,
	enc_uninit,
	enc_methods,
	0
};

#else

MSFilterDesc amrwb_enc_desc = {
	.id = MS_FILTER_PLUGIN_ID,
	.name = "MSAMRWBEnc",
	.text = "AMR Wideband encoder",
	.category = MS_FILTER_ENCODER,
	.enc_fmt = "AMR-WB",
	.ninputs = 1,
	.noutputs = 1,
	.init = enc_init,
	.process = enc_process,
	.uninit = enc_uninit,
	.methods = enc_methods
};

#endif
