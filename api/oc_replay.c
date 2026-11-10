/*
 * Copyright (c) 2020 Intel Corporation
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "oc_replay.h"
#include "port/oc_clock.h"
#include "oc_config.h"
#include "oc_knx_sec.h"

#ifndef OC_MAX_REPLAY_RECORDS
// number belongs to publishers from that we MAY get an inbound message, if less than that the oldest will be evicted.   
#define OC_MAX_REPLAY_RECORDS (KNX_GPT_MAX_ENTRIES)
#endif

typedef struct oc_replay_record
{
	oc_clock_time_t time;                       // time of last received client packet
	uint32_t rx_ssn;                            // most recent received client SSN (32-bit, KNX IoT)
	uint32_t window;                            // bitfield of received SSNs, 32-bit = OSCORE RFC default
	uint8_t  rx_kid[OSCORE_SENDER_ID_LEN];      // client KID (raw bytes, same layout as oc_endpoint_t)
	uint8_t  rx_kid_len;
	uint8_t  rx_kid_ctx[OSCORE_ID_CONTEXT_LEN]; // client KID context (raw bytes, can be empty)
	uint8_t  rx_kid_ctx_len;
	bool     in_use;                            // whether this record holds valid data
} oc_replay_record_t;

static oc_replay_record_t replay_records[OC_MAX_REPLAY_RECORDS] = { 0 };

/*
  The window is a bitfield with one bit per SSN, a larger window would shift past its width (undefined behaviour)
*/
static_assert(OSCORE_REPLAY_WINDOW_SIZE <= sizeof(replay_records[0].window) * 8, "OSCORE_REPLAY_WINDOW_SIZE exceeds the window bitfield");

// clear all replay window records
void oc_oscore_free_all_replay_records(void)
{
	for (int i = 0; i < OC_MAX_REPLAY_RECORDS; i++)
	{
    // c pointer arithmetics
    oc_replay_record_t* rec = replay_records + i;

	  rec->in_use = false;
	}
	OC_DBG("Cleared all replay window records");
}

// find empty record in queue, if queue is full ... free oldest record
static oc_replay_record_t* get_empty_record(void)
{
	for (int i = 0; i < OC_MAX_REPLAY_RECORDS; i++)
	{
    // c pointer arithmetics
    struct oc_replay_record* rec = replay_records + i;

	  if (!rec->in_use)
    {
      return rec;
    }
	}
	// nothing free, free oldest record 

	// defines oldest record as first array element
	oc_replay_record_t* oldest_rec = replay_records;

	// finding of oldest record, to release it (on heap limitations) 
	for (int i = 1; i < OC_MAX_REPLAY_RECORDS; i++)
	{
		// c pointer arithmetics
		oc_replay_record_t* rec = replay_records + i;

	  if (rec->time < oldest_rec->time)
    {
      oldest_rec = rec;
    }
	}

	// clearing it marks the record as free
	oldest_rec->in_use = false;
	return oldest_rec;
}

// find record matching 'kid' and 'kid context' from the inbound endpoint (also empty kid contexts are a match)
static oc_replay_record_t* get_record(const oc_endpoint_t* endpoint)
{
	if (endpoint->kid_len == 0)
	{
    // rx kid not present -> a match is not applicable
	  return NULL; 
	}

	for (int i = 0; i < OC_MAX_REPLAY_RECORDS; i++)
	{
		// c pointer arithmetics
		oc_replay_record_t* rec = replay_records + i;

		if (rec->in_use)
		{
			const bool rx_kid_match = rec->rx_kid_len == endpoint->kid_len &&  
				memcmp(rec->rx_kid, endpoint->kid, endpoint->kid_len) == 0;
			
		  const bool kid_context_match = rec->rx_kid_ctx_len == endpoint->kid_ctx_len && 
				memcmp(rec->rx_kid_ctx, endpoint->kid_ctx, endpoint->kid_ctx_len) == 0;

			/* 
			  - kid match
			  - kid context match
          - nonempty -> 2 x kid context are present 
			    - empty -> 2 x kid context are not present and hence len is 0 ('memcmp(..., 0)' → with size 0 always returns 0 → true)
			*/
      if (rx_kid_match && kid_context_match)
      {
        return rec;
      }
		}
	}
	return NULL;  // nothing found
}

replay_state_t oc_replay_check_client(uint32_t rx_ssn, const oc_endpoint_t* endpoint)
{

	/*
	With CoAP over UDP, you cannot guarantee messages are received in order,
	hence SSN needs to be checked against replayed SSNs.

	We can use the default anti-replay algorithm specified by OSCORE, which
	uses a sliding window in order to track every received SSN within a
	given range.

	This can be implemented very efficiently using a bitfield, where the
	position of bits indicate the SSN being considered, and the value
	of the bit indicates whether the packet has been received before

	The entire bitfield is LEFT shifted whenever the recorded SSN increases,
	thus 'sliding' the (left) window in a very efficient manner. Here's an example
	of the algorithm in operation, with a REDUCED 8-bit bitfield for readability:

																		 1234 5678
	max received ssn = 8, bitfield = 0b0000'0001
	rcv ssn 6, 8 - 6 = bit 2, inside window + free -> accept delayed msg, set bit 2 
	:
	max received ssn = 8, bitfield = 0b0000'0101
	rcv ssn 0, 8 - 0 = bit 8, left side window -> send echo for unknown msg 
	:
	:
	max received ssn = 8, bitfield = 0b0000'0101
	rcv ssn 8, 8 - 8 = bit 0, inside window + blocked -> throw replayed msg with ssn 8
	:
	:
	max received ssn = 8, bitfield = 0b0000'0101
	rcv ssn 9, 8 - 9 = bit -1, right side window -> accept fresh msg, update ssn, 1 x l-shift bitfield, set bit 0
	:
	:                                  2345 6789
	max received ssn = 9, bitfield = 0b0000'1011
	rcv ssn 99, 9 - 99 = bit -90, right side window -> accept fresh msg, update ssn, 90 x l-shift bitfield, set bit 0
	:
	:                                           99
	max received ssn = 99, bitfield = 0b0000'0001
	:
	*/

	/*
		no record found -> challenge with echo option, either on first pub message
		or after a release of an old recipient context
	*/
	oc_replay_record_t* rec = get_record(endpoint);
	if (!rec)
	{
		return ECHO;
	}

	// record matched -> keep it around, update the time (to prevent a release from heap)
	rec->time = oc_clock_time();

	/*
		exact difference of two 32-bit SSNs, both widened to 64 bit INT before subtraction (no 32-bit overflow)
		- an SSN far below the recorded one lands out of the left window bound, e.g. a peer that lost its stored SSN
			=> ECHO, intended, the peer re-synchronises via the echo exchange (oc_replay_add_client)
	*/
	const int64_t ssn_diff = (int64_t)rec->rx_ssn - (int64_t)rx_ssn;
	const int64_t wnd_size = OSCORE_REPLAY_WINDOW_SIZE;

	OC_DBG("ssn new/old = %" PRIx32 "/%" PRIx32 ", diff = %" PRIi64 ", wnd = %" PRIx32, rx_ssn, rec->rx_ssn, ssn_diff, rec->window);
	OC_DBG("kid (%u)\t= %.*s", (unsigned)endpoint->kid_len, (int)endpoint->kid_len, (const char*)endpoint->kid);
	OC_DBG("kid ctx (%u)\t= %.*s", (unsigned)endpoint->kid_ctx_len, (int)endpoint->kid_ctx_len, (const char*)endpoint->kid_ctx);

	if (ssn_diff >= wnd_size)
	{
		OC_DBG("left of window by %" PRIi64 " -> echo", ssn_diff);
		return ECHO; // not known if it was (ever) received before
	}

	if (ssn_diff >= 0)
	{
		const uint32_t bit = (uint32_t)1 << ssn_diff;
		if (rec->window & bit)
		{
		  OC_DBG("inside window at bit %" PRIi64 " -> replay", ssn_diff);
			return REPLAY; // SSN received before
		}

		rec->window |= bit;
		OC_DBG("inside window at bit %" PRIi64 " -> synced, wnd = %" PRIx32, ssn_diff, rec->window);
		return SYNCED; // SSN NOT received before, tick the bit; DO NOT update rx_ssn (not the max)
	}

	// fresh message: slide the window (shift >= type width is undefined -> zero manually), set bit 0, remember new max SSN
	if (-ssn_diff >= wnd_size)
	{
		rec->window = 0;
	}
	else
	{
		rec->window <<= -ssn_diff;
	}
	rec->window |= 1;
	rec->rx_ssn = rx_ssn;

	OC_DBG("right of window by %" PRIi64 " -> synced, wnd = %" PRIx32, -ssn_diff, rec->window);
	return SYNCED;
}

void oc_replay_add_client(uint32_t rx_ssn, const oc_endpoint_t* endpoint)
{
	oc_replay_record_t* rec = get_record(endpoint);

	if (!rec)
	{ // no match on first try - get a free record
		rec = get_empty_record();
		memcpy(rec->rx_kid, endpoint->kid, endpoint->kid_len);
		rec->rx_kid_len = endpoint->kid_len;
		memcpy(rec->rx_kid_ctx, endpoint->kid_ctx, endpoint->kid_ctx_len);
		rec->rx_kid_ctx_len = endpoint->kid_ctx_len;
		rec->in_use = true;
	}

	/* 
	 - reinit record with fresh SSN + window (and tick the new ssn as already used),
	 - the option to receive possible older SSNs within the present/old window (if it was present and not a free record) is gone
    */
	rec->rx_ssn = rx_ssn;
	rec->window = 1;
	rec->time = oc_clock_time();
}