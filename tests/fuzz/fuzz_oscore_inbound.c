/*
 * libFuzzer harness for the inbound OSCORE request path beyond decryption
 * (security/oc_oscore_engine.c) on an initialised stack.
 *
 * Without a valid AEAD tag every mutated message stops at decryption, so
 * the parsers of fuzz_coap_inbound and fuzz_oscore_options never see what a
 * peer with a credential sends: the inner options, the inner code, the replay
 * window and the access check in front of every secured resource. Here an
 * access token with a known secret and every scope is installed, the harness
 * derives the recipient key the device derives from it, and each input record
 * is the PLAINTEXT of an OSCORE request that the harness encrypts and wraps
 * in an outer CoAP message before it is injected as a received datagram. The
 * device then creates its own recipient context from the token, decrypts,
 * parses the inner message, checks the replay window and dispatches it, and
 * encrypts its response with its sender context.
 *
 * Input: [flags] then up to 8 records [sel][len_hi][len_lo][plaintext].
 *   flags bit 0: the device is in runtime (LSM loaded, ia and iid set)
 *   flags bit 1: no Echo synchronisation first (see synchronise())
 *   plaintext:   inner code, inner options, 0xFF and payload (RFC 8613 5.3)
 *   sel bit 0:   multicast destination     bit 1: NON (else CON)
 *   sel bit 2:   outer code FETCH (else POST)
 *   sel bits 3-4: kid context 0 none, 1 8 bytes, 2 10 bytes, 3 none
 *   sel bit 5:   reuse the previous SSN (a replay), else the next SSN
 *   sel bit 6:   unknown kid (no access token)
 *   sel bit 7:   corrupt the tag
 */

#include "fuzz_stack.h"
#include "messaging/coap/coap.h"
#include "messaging/coap/constants.h"
#include "messaging/coap/oscore.h"
#include "messaging/coap/oscore_constants.h"
#include "port/oc_clock.h"
#include "security/oc_oscore_context.h"
#include "security/oc_oscore_crypto.h"

#define MAX_RECORDS 8
#define NUM_KID_CTX 3

/* the flags byte at the start of the input */
#define FLAG_RUNTIME 0x01
#define FLAG_NO_ECHO_SYNC 0x02

/* the sel byte of a record */
#define SEL_MULTICAST 0x01 /* the same bit as in fuzz_make_endpoint */
#define SEL_NON 0x02
#define SEL_FETCH 0x04
#define SEL_KID_CTX_SHIFT 3
#define SEL_KID_CTX_MASK 0x03
#define SEL_SAME_SSN 0x20
#define SEL_UNKNOWN_KID 0x40
#define SEL_BAD_TAG 0x80

/* fuzz_make_endpoint selector of the peer that holds the token */
#define PEER_EP 0x30

/* outer token: a fixed first byte plus the low byte of the MID */
#define TOKEN_LEN 2
#define TOKEN_FIRST_BYTE 0x0F

#define PAYLOAD_MARKER 0xFF
/* option header byte + 2 bytes extended delta + 2 bytes extended length */
#define MAX_OPTION_HEADER_LEN 5

extern const oc_resource_t core_resource_knx_auth_at;

static const uint8_t k_kid[] = {0x01};
static const uint8_t k_unknown_kid[] = {0x02};

/* [{0:"osc", 9:[all scopes], 38:2, 8:{4:{0:h'01', 2:h'0102..10'}}}] */
static const uint8_t k_at[] = {
  0x81, 0xA4, 0x00, 0x63, 'o',  's',  'c',  0x09, 0x8A, 0x64, 'i',  'f',  '.',  'i',  0x64, 'i',  'f',  '.',  'o',  0x66, 'i',  'f',  '.',  'g',
  '.',  's',  0x64, 'i',  'f',  '.',  'c',  0x64, 'i',  'f',  '.',  'p',  0x64, 'i',  'f',  '.',  'd',  0x64, 'i',  'f',  '.',  'a',  0x64, 'i',
  'f',  '.',  's',  0x66, 'i',  'f',  '.',  's',  'e',  'c',  0x66, 'i',  'f',  '.',  's',  'w',  'u',  0x18, 0x26, 0x02, 0x08, 0xA1, 0x04, 0xA2,
  0x00, 0x41, 0x01, 0x02, 0x50, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
};

static const uint8_t k_kid_ctx_8[] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7};
/* 10 bytes is also the length of an echo kid context */
static const uint8_t k_kid_ctx_10[] = {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9};

typedef struct
{
  const uint8_t* kid_ctx;
  uint8_t kid_ctx_len;
  uint8_t key[OSCORE_KEY_LEN];
  uint8_t common_iv[OSCORE_COMMON_IV_LEN];
} peer_keys_t;

static peer_keys_t g_keys[NUM_KID_CTX] = {
  {NULL, 0, {0}, {0}},
  {k_kid_ctx_8, sizeof(k_kid_ctx_8), {0}, {0}},
  {k_kid_ctx_10, sizeof(k_kid_ctx_10), {0}, {0}},
};

static oc_endpoint_t g_mac;
static uint16_t g_mid;

static void install_token(void)
{
  const int code = fuzz_call_res(&core_resource_knx_auth_at, &core_resource_knx_auth_at.post_handler, COAP_POST, &g_mac, k_at, sizeof(k_at), NULL, 0);
  if (code != oc_status_code(OC_STATUS_CHANGED) && code != oc_status_code(OC_STATUS_CREATED))
  {
    fprintf(stderr, "fixture: auth/at POST returned %d\n", code);
    abort(); /* fixture broken: every record would end at 'no access token' */
  }
}

/* The keys depend only on the token and the kid context, so they are derived
 * once with the device's own derivation and the contexts dropped again: the
 * device creates its recipient context itself on the first request. */
static void derive_keys(void)
{
  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));
  memcpy(pkt.kid, k_kid, sizeof(k_kid));
  pkt.kid_len = sizeof(k_kid);
  const oc_auth_at_t* at = oc_core_find_at_entry_by_osc_id(&pkt);
  if (at == NULL)
  {
    abort();
  }
  for (int i = 0; i < NUM_KID_CTX; i++)
  {
    oc_oscore_context_params_t params;
    memset(&params, 0, sizeof(params));
    params.id_context = g_keys[i].kid_ctx;
    params.id_context_size = g_keys[i].kid_ctx_len;
    params.auth_at = at;
    oc_oscore_context_t* ctx = oc_oscore_add_recipient_context(&params);
    if (ctx == NULL)
    {
      abort();
    }
    memcpy(g_keys[i].key, ctx->recipient_key, OSCORE_KEY_LEN);
    memcpy(g_keys[i].common_iv, ctx->common_iv, OSCORE_COMMON_IV_LEN);
    oc_oscore_free_context(ctx);
  }
}

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
  (void)argc;
  (void)argv;
  fuzz_stack_init();
  fuzz_make_endpoint(&g_mac, FUZZ_EP_MAC, true);
  install_token();
  derive_keys();
  fuzz_stack_reset();
  return 0;
}

/* appends one CoAP option (header + value) at buf[*len] */
static void put_option(uint8_t* buf, size_t* len, unsigned delta, const void* value, size_t value_len)
{
  *len += coap_set_option_header(delta, value_len, buf + *len);
  memcpy(buf + *len, value, value_len);
  *len += value_len;
}

static void send_record(uint8_t sel, uint32_t ssn, const uint8_t* plain, size_t plain_len)
{
  const peer_keys_t* keys = &g_keys[((sel >> SEL_KID_CTX_SHIFT) & SEL_KID_CTX_MASK) % NUM_KID_CTX];
  const uint8_t* kid = (sel & SEL_UNKNOWN_KID) ? k_unknown_kid : k_kid;
  const uint8_t kid_len = sizeof(k_kid);

  uint8_t piv[OSCORE_PIV_LEN];
  uint8_t piv_len = 0;
  oscore_store_ssn_to_piv(piv, &piv_len, ssn);

  /* OSCORE option value: flags, PIV, kid context, kid (RFC 8613 6.1) */
  uint8_t option[OSCORE_MAX_OPTION_VALUE_LEN];
  size_t option_len = 0;
  option[option_len++] = (uint8_t)(piv_len | OSCORE_FLAGS_KID_BITMASK | (keys->kid_ctx_len > 0 ? OSCORE_FLAGS_KIDCTX_BITMASK : 0));
  memcpy(option + option_len, piv, piv_len);
  option_len += piv_len;
  if (keys->kid_ctx_len > 0)
  {
    option[option_len++] = keys->kid_ctx_len;
    memcpy(option + option_len, keys->kid_ctx, keys->kid_ctx_len);
    option_len += keys->kid_ctx_len;
  }
  memcpy(option + option_len, kid, kid_len);
  option_len += kid_len;

  uint8_t pdu[OC_PDU_SIZE];
  const size_t header_len = COAP_HEADER_LEN + TOKEN_LEN + MAX_OPTION_HEADER_LEN + option_len + COAP_PAYLOAD_MARKER_LEN;
  if (header_len + plain_len + OSCORE_AEAD_TAG_LEN > sizeof(pdu))
  {
    plain_len = sizeof(pdu) - header_len - OSCORE_AEAD_TAG_LEN;
  }

  g_mid++;
  const coap_message_type_t type = (sel & SEL_NON) ? COAP_TYPE_NON : COAP_TYPE_CON;
  size_t len = 0;
  pdu[len++] =
    (uint8_t)(COAP_VERSION << COAP_HEADER_VERSION_POSITION | type << COAP_HEADER_TYPE_POSITION | TOKEN_LEN << COAP_HEADER_TOKEN_LEN_POSITION);
  pdu[len++] = (sel & SEL_FETCH) ? COAP_FETCH : COAP_POST;
  pdu[len++] = (uint8_t)(g_mid >> 8);
  pdu[len++] = (uint8_t)g_mid;
  pdu[len++] = TOKEN_FIRST_BYTE;
  pdu[len++] = (uint8_t)g_mid;
  put_option(pdu, &len, COAP_OPTION_OSCORE, option, option_len);
  pdu[len++] = PAYLOAD_MARKER;

  /* the device builds AAD and nonce from its recipient id, which is the kid */
  uint8_t aad[OSCORE_AAD_MAX_LEN];
  uint8_t aad_len = sizeof(aad);
  uint8_t nonce[OSCORE_AEAD_NONCE_LEN];
  oc_oscore_compose_AAD((uint8_t*)kid, kid_len, piv, piv_len, aad, &aad_len);
  oc_oscore_AEAD_nonce((uint8_t*)kid, kid_len, piv, piv_len, (uint8_t*)keys->common_iv, nonce, sizeof(nonce));
  if (oc_oscore_encrypt(plain, plain_len, OSCORE_AEAD_TAG_LEN, keys->key, OSCORE_KEY_LEN, nonce, sizeof(nonce), aad, aad_len, pdu + len) != 0)
  {
    return;
  }
  len += plain_len + OSCORE_AEAD_TAG_LEN;
  if (sel & SEL_BAD_TAG)
  {
    pdu[len - 1] ^= 0x01; /* flip one bit of the tag */
  }

  oc_endpoint_t from;
  fuzz_make_endpoint(&from, (uint8_t)(PEER_EP | (sel & SEL_MULTICAST)), false);
  fuzz_inject(pdu, len, &from);
}

/*
 * A peer the device has no replay window for gets 4.01 with an Echo option
 * first (RFC 9175); only the repeated request carrying that Echo value is
 * dispatched. The Echo value is the device's clock, accepted while fresh, so
 * the harness answers the challenge the way a client does: one GET /dev/sn per
 * kid context with the current time as Echo, after which the fuzzed records
 * reach the handlers. Flag bit 1 skips this to keep the unsynchronised paths.
 */
static void synchronise(uint32_t* ssn)
{
  static const char k_dev[] = "dev";
  static const char k_sn[] = "sn";
  const oc_clock_time_t now = oc_clock_time();
  uint8_t plain[1 + 3 * MAX_OPTION_HEADER_LEN + sizeof(k_dev) + sizeof(k_sn) + sizeof(now)];
  size_t len = 0;
  plain[len++] = COAP_GET;
  put_option(plain, &len, COAP_OPTION_URI_PATH, k_dev, strlen(k_dev));
  put_option(plain, &len, 0, k_sn, strlen(k_sn));
  put_option(plain, &len, COAP_OPTION_ECHO - COAP_OPTION_URI_PATH, &now, sizeof(now));

  for (uint8_t i = 0; i < NUM_KID_CTX; i++)
  {
    send_record((uint8_t)(i << SEL_KID_CTX_SHIFT), (*ssn)++, plain, len);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  if (size < 1)
  {
    return 0;
  }
  const uint8_t flags = data[0];
  install_token();
  if (flags & FLAG_RUNTIME)
  {
    fuzz_set_ia_and_iid();
    oc_core_get_device_info()->lsm_s = LSM_S_LOADED;
  }

  uint32_t ssn = 0;
  if ((flags & FLAG_NO_ECHO_SYNC) == 0)
  {
    synchronise(&ssn);
  }

  size_t pos = 1;
  uint8_t sel;
  const uint8_t* plain;
  size_t len;
  for (int i = 0; i < MAX_RECORDS && fuzz_next_record(data, size, &pos, &sel, &plain, &len); i++)
  {
    if ((sel & SEL_SAME_SSN) == 0)
    {
      ssn++;
    }
    send_record(sel, ssn, plain, len);
  }
  fuzz_stack_reset();
  return 0;
}
