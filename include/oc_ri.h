/*
 * Copyright (c) 2016-2019 Intel Corporation
 * Copyright (c) 2021 Cascoda Ltd
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

#pragma once

#ifndef __ZEPHYR__
#include "ipadapter.h"
#endif
#include "oc_config.h"
#include "oc_endpoint.h"
#include "oc_rep.h"
#include "util/oc_etimer.h"
#include "messaging/coap/constants.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The blockwise state is only forward declared here, oc_blockwise.h includes this header. */
struct oc_blockwise_state_s;

/**
 * @brief CoAP observe codes, see https://www.rfc-editor.org/rfc/rfc7641#section-2
 *
*/
typedef enum
{
  OC_OBSERVE_NOT_INITIALIZED = -1,
  OC_OBSERVE_REGISTER = 0,         // client request: register as observer
  OC_OBSERVE_DEREGISTER = 1,       // client request: deregister as observer
  OC_OBSERVE_NOT_APPLICABLE = 2,   // no observe option present (e.g. a normal one-off request/response)
  OC_OBSERVE_NOTIFICATIONS = 3,    // notification sequence number (always > the reserved 0/1/2 values)
} oc_client_observe_t;

/**
 * @brief resource properties (bit mask)
 * 
 * OC_WRITE_AFFECTS_FP
 * 
 * - Specify that a write request to the resource changes the application fingerprint.
 * - Must be set by vendor in relation if a change of value affects the fingerprint.
 *   It is NOT checked by stack if the actual written value really changes the original value,
 *   the aspect of a POST/PUT is the only criteria.
 * - What is covered by the fingerprint, see KNX IoT specification.
 * 
 * OC_OBSERVABLE
 * 
 * - Specify that a resource should notify clients when a property has been modified.
 * - A cyclic notification time can be set with 'oc_resource_set_periodic_observable'.
 * - usually resources with if.o/ if.g.s interface are observable (others are a vendor/ application decision).
 * - if.o AND if.i SHALL not be used together
 */
typedef enum {
  OC_NO_PROPERTIES = 0,		       /**< no properties are set at all, means that all other properties are false */
  OC_DISCOVERABLE = 1 << 1,            /**< resource can be discovered (true) or not (false) */
  OC_OBSERVABLE = 1 << 2,              /**< resource can be observed (true) or not (false) */
  OC_PERIODIC = 1 << 3,                /**< the resource will cyclically send a periodical notification update, details on enum definition */ 
  OC_WRITE_AFFECTS_FP = 1 << 4,        /**< write (PUT/POST) access affects fingerprint, must be set by vendor, details on enum definition */
} oc_resource_properties_t;

/**
* @brief CoAP status codes
*
* Note: can be translated to HTTP or CoAP.
*
* @see oc_status_code for translation to the CoAP status codes
*/
typedef enum {
  OC_STATUS_OK = 0,                    /**< Content 2.05 */
  OC_STATUS_CREATED,                   /**< Created 2.01 */
  OC_STATUS_CHANGED,                   /**< Changed 2.04 */
  OC_STATUS_DELETED,                   /**< Deleted 2.02 */
  OC_STATUS_NOT_MODIFIED,              /**< Not Modified (VALID 2.03) */
  OC_STATUS_BAD_REQUEST,               /**< Bad Request 4.00*/
  OC_STATUS_UNAUTHORIZED,              /**< Unauthorized 4.01*/
  OC_STATUS_BAD_OPTION,                /**< Bad Option 4.02*/
  OC_STATUS_FORBIDDEN,                 /**< Forbidden 4.03*/
  OC_STATUS_NOT_FOUND,                 /**< Not Found 4.04*/
  OC_STATUS_METHOD_NOT_ALLOWED,        /**< Method Not Allowed 4.05*/
  OC_STATUS_NOT_ACCEPTABLE,            /**< Not Acceptable 4.06 */
  OC_STATUS_REQUEST_ENTITY_TOO_LARGE,  /**< Request Entity Too Large 4.13*/
  OC_STATUS_UNSUPPORTED_MEDIA_TYPE,    /**< Unsupported Media Type 4.15*/
  OC_STATUS_INTERNAL_SERVER_ERROR,     /**< Internal Server Error 5.00 */
  OC_STATUS_NOT_IMPLEMENTED,           /**< Not Implemented 5.01*/
  OC_STATUS_BAD_GATEWAY,               /**< Bad Gateway 5.02*/
  OC_STATUS_SERVICE_UNAVAILABLE,       /**< Service Unavailable 5.03*/
  OC_STATUS_GATEWAY_TIMEOUT,           /**< Gateway Timeout 5.04*/
  OC_STATUS_PROXYING_NOT_SUPPORTED,    /**< Proxying not supported 5.05 */
  NUMBER_OF_OC_STATUS_CODES,           // artificial code to count above codes
  OC_IGNORE                            /**< Ignore, do not respond to a request */
} oc_status_t;

/**
* @brief payload content formats
*
* https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#rd-parameters
*
*/
typedef enum oc_content_format {
  TEXT_PLAIN = 0,                      /**< text/plain */
  TEXT_XML = 1,                        /**< text/xml */
  TEXT_CSV = 2,                        /**< text/csv */
  TEXT_HTML = 3,                       /**< text/html */
  IMAGE_GIF = 21,                      /**< image/gif - not used */
  IMAGE_JPEG = 22,                     /**< image/jpeg - not used */
  IMAGE_PNG = 23,                      /**< image/png - not used */
  IMAGE_TIFF = 24,                     /**< image/tiff - not used */
  AUDIO_RAW = 25,                      /**< audio/raw - not used */
  VIDEO_RAW = 26,                      /**< video/raw - not used */
  APPLICATION_LINK_FORMAT = 40,        /**< application/link-format */
  APPLICATION_XML = 41,                /**< application/xml */
  APPLICATION_OCTET_STREAM = 42,       /**< application/octet-stream */
  APPLICATION_RDF_XML = 43,            /**< application - not used */
  APPLICATION_SOAP_XML = 44,           /**< application/soap - not used */
  APPLICATION_ATOM_XML = 45,           /**< application - not used */
  APPLICATION_XMPP_XML = 46,           /**< application - not used */
  APPLICATION_EXI = 47,                /**< application/exi */
  APPLICATION_FASTINFOSET = 48,        /**< application */
  APPLICATION_SOAP_FASTINFOSET = 49,   /**< application */
  APPLICATION_JSON = 50,               /**< application/json */
  APPLICATION_X_OBIX_BINARY = 51,      /**< application - not used */
  APPLICATION_CBOR = 60,               /**< application/cbor */
  APPLICATION_SENML_JSON = 110,        /**< application/senml+json */
  APPLICATION_SENSML_JSON = 111,       /**< application/sensml+json */
  APPLICATION_SENML_CBOR = 112,        /**< application/senml+cbor */
  APPLICATION_SENSML_CBOR = 113,       /**< application/sensml+cbor */
  APPLICATION_SENML_EXI = 114,         /**< application/senml-exi */
  APPLICATION_SENSML_EXI = 115,        /**< application/sensml-exi */
  APPLICATION_PKCS7_SGK = 280,         /**< application/pkcs7-mime; smime-type=server-generated-key */
  APPLICATION_PKCS7_CO = 281,          /**<< application/pkcs7-mime; smime-type=certs-only */
  APPLICATION_PKCS7_CMC_REQUEST = 282, /**< application/pkcs7-mime; smime-type=CMC-Request */
  APPLICATION_PKCS7_CMC_RESPONSE = 283,        /**< application/pkcs7-mime; smime-type=CMC-Response */
  APPLICATION_PKCS8 = 284,             /**< application/pkcs8 */
  APPLICATION_CRATTRS = 285,           /**< application/csrattrs */
  APPLICATION_PKCS10 = 286,            /**< application/pkcs10 */
  APPLICATION_PKIX_CERT = 287,         /**< application/pkix-cert */
  APPLICATION_VND_OCF_CBOR = 10000,    /**< application/vnd.ocf+cbor */
  APPLICATION_OSCORE = 10001,          /**< application/oscore */
  APPLICATION_VND_OMA_LWM2M_TLV = 11542,       /**< application/vnd.oma.lwm2m+tlv */
  APPLICATION_VND_OMA_LWM2M_JSON = 11543,      /**< application/vnd.oma.lwm2m+json */
  APPLICATION_VND_OMA_LWM2M_CBOR = 11544,      /**< application/vnd.oma.lwm2m+cbor */
  /*
    Internal 'no content format' marker, NOT an IANA CoAP Content-Format.

    Taken from the 64998-64999 block that the IANA CoAP Content-Formats registry reserves for
    documentation, so it can never collide with an operationally assigned format, and it fits the
    uint16_t that coap_packet_t uses for content_format and accept. 
    
    The previous value 99999 was outside the 0-65535 registry range and silently truncated to 34463
    when stored in those fields, which lands in the 33000-64997 Expert Review range and is therefore
    indistinguishable from a real assignment.

    - application layer only (oc_request_t)
    - not passed by coap_set_header_content_format() on the wire by omitting the option
    - clause 2.2.4 defines what a receiver assumes then, the default format of the corresponding 
      device resource
  */
  CONTENT_NONE = 64999
} oc_content_format_t;

/**
 * @brief a structure that hosts the origin request and a response state,
 *        that tracks the process/schedule of origin request -> delayed response
 *
 */
typedef struct oc_separate_response_s oc_separate_response_t;

/**
 * @brief response buffer type
 *
 */
typedef struct oc_response_buffer_s oc_response_buffer_t;

/**
 * @brief response type
 *
 */
typedef struct oc_response_t {
  oc_separate_response_t* separate_response; /**< tracking structure for a separate response */
  oc_response_buffer_t* response_buffer;     /**< the actual used response buffer */
} oc_response_t;

/**
 * @brief interface mask
 *
 */
typedef enum oc_interface_mask {
  OC_IF_NONE = 0,                      /**< no interface, defined as 0 (not 1) to not count this as an interface */
  OC_IF_I = 1 << 1,                    /**< if.i (logical input) */
  OC_IF_O = 1 << 2,                    /**< if.o (logical output) */
  OC_IF_G = 1 << 3,                    /**< if.g.s. (all or some group addresses) */
  OC_IF_C = 1 << 4,                    /**< if.c (configuration) */
  OC_IF_P = 1 << 5,                    /**< if.p (parameter) */
  OC_IF_D = 1 << 6,                    /**< if.d (diagnostic) */
  OC_IF_A = 1 << 7,                    /**< if.a (HW actuator) */
  OC_IF_S = 1 << 8,                    /**< if.s (HW sensor) */
  OC_IF_LI = 1 << 9,                   /**< if.ll */
  OC_IF_B = 1 << 10,                   /**< if.b */
  OC_IF_SEC = 1 << 11,                 /**< if.sec */
  OC_IF_SWU = 1 << 12,                 /**< if.swu */
  OC_IF_PM = 1 << 13,                  /**< if.pm */
  OC_IF_M = 1 << 14                    /**< if.m.x (manufacturer specific) */
} oc_interface_mask_t;

#define MAX_INTERFACE_BIT (14) // the highest 'defined' valid interface bit-position
#define NUM_INTERFACES    (15) // the number of interfaces in the array

/**
 * @brief access control (acl) scopes, derived from interfaces
 *
 */
typedef enum {
  OC_ACL_NONE = OC_IF_NONE,            /**< no scope, defined as 0 (not 1) to not count this as a scope */
  OC_ACL_I = OC_IF_I,                  /**< if.i (logical input) */
  OC_ACL_O = OC_IF_O,                  /**< if.o (logical output) */
  OC_ACL_G = OC_IF_G,                  /**< if.g.s (all ga's are allowed, see oc_knx_sec_check_acl) */
  OC_ACL_C = OC_IF_C,                  /**< if.c (configuration) */
  OC_ACL_P = OC_IF_P,                  /**< if.p (parameter) */
  OC_ACL_D = OC_IF_D,                  /**< if.d (diagnostic) */
  OC_ACL_A = OC_IF_A,                  /**< if.a (HW actuator) */
  OC_ACL_S = OC_IF_S,                  /**< if.s (HW sensor) */
		                                   /* if.ll (is not a scope) */
		                                   /* if.b  (is not a scope) */
  OC_ACL_SEC = OC_IF_SEC,              /**< if.sec  */
  OC_ACL_SWU = OC_IF_SWU,              /**< if.swu  */
	                                     /* if.pm (is not a scope) */
		                                   /* if.m.x (is not a scope) */
  OC_ACL_GA = OC_IF_M << 1             /**< <ga> ([owl]some ga's are allowed, see oc_knx_sec_check_acl), is ONLY an INTERNAL scope and has no corr. interface */
} oc_acl_mask_t;

#define MAX_ACL_SCOPE_BIT (12)	// the highest 'defined' valid scope bit-position (note, the <ga> scope is internal and not considered)
#define NUM_ACL_SCOPES    (16)	// the number of scopes in the array

/**
 * @brief Get the interface string object from a corresponding interface bit
 *
 * @param index the interface mask (array) index 
 * @return const char* the interface as full URN string e.g. "urn:knx:if.i"
 *
 */
const char* get_interface_string_full_urn(int index);

/**
 * @brief counts the number of total scopes in a mask
 *
 * @param scopes the scope mask
 * @return int the amount of scopes in the mask
 *
 */
unsigned int oc_count_total_scopes_in_mask(oc_acl_mask_t scopes);

/**
 * @brief counts the number of total interfaces in a mask
 *
 * @param interfaces the interface mask
 * @return int the amount of interfaces in the mask
 *
 * @note calculates the interface if.g.s.<a> only 1
 *
 */
unsigned int oc_count_total_interfaces_in_mask(oc_interface_mask_t interfaces);

/**
 * @brief returns the corresponding oc_status code from coap code
 *
 * @param coap_code the coap code
 * @return the oc_status code or OC_IGNORE if not found
 *
 *	@note the oc_status number 0...n from enum is needed, not the actual coap code number 
 *
 */
oc_status_t get_oc_status_code_from_coap_code(int coap_code);

/**
 * @brief sets all access scopes in a mask in a string array with scope names
 *
 * @param scopes the scope mask
 * @param scopes_array the string array to place the individual scope NAMES in
 *
 * @note example data = [ "if.sec", "if.p" ]
 * 
 */
void oc_put_all_access_scope_names_from_a_mask_in_string_array(oc_acl_mask_t scopes, oc_string_array_t scopes_array);

/**
 * @brief set all interfaces in a mask in a string array with interface short URNs
 *
 * @param interfaces the interface mask
 * @param scopes_array the string array to place the individual interface SHORT URN's in
 *
 * @note example data = [ ":if.sec", ":if.p" ]
 * 
 */
void oc_put_all_interface_short_urns_from_a_mask_in_string_array(oc_interface_mask_t interfaces, oc_string_array_t scopes_array);

/**
 * @brief prints all acl scopes in the mask to stdout
 *
 * @param scope the scope mask names in
 */
void oc_print_acl_scopes(oc_acl_mask_t scope);

/**
 * @brief core resource numbers
 *
 * @note
 *
 * - the numbered order of resources is used to create the 'linked' list
 *   of resources, hence the pointer to a specific resource matches
 *   the number in this enum (used for get 'resource by index' functions)
 *
 * - if inserting a new resource, add them in the enum in that place where
 *	 as the linked list linkage is defined
 *
 * - some enums are used to calculate the number of resources, such as
 *   OC_DEV - OC_DEV_SN (all device resources)
 *
 */
typedef enum {
  OC_DEV_SN = 0,                       /**< Device serial number */
  OC_DEV_HWV,                          /**< Hardware version */
  OC_DEV_FWV,                          /**< Firmware version */
  OC_DEV_HWT,                          /**< The hardware type is a manufacture specific id for a device type (MaC uses this id for compatibility checks) */
  OC_DEV_ORDER_NUMBER,                 /**< Device order number (former device model) */
  OC_DEV_HOSTNAME,                     /**< Device host name for DNS resolution. */
  OC_DEV_IID,                          /**< KNX installation ID */
  OC_DEV_PM,                           /**< Programming Mode */
  OC_DEV_IPV6,                         /**< IPV6 */
  OC_DEV_SA,                           /**< /dev/sa subnet address */
  OC_DEV_DA,                           /**< /dev/da device address */
  OC_DEV_FID,                          /**< /dev/fid the fabric ID */
  OC_DEV_PORT,                         /**< /dev/port the coap port number */
  OC_DEV_MPORT,                        /**< /dev/mport the multicast port number */
  OC_DEV_MID,                          /**< /dev/mid the manufacturer ID */
  OC_DEV,                              /**< core link */
  OC_APP,                              /**< application ID (list) */
  OC_APP_PV,                           /**< application program version */
  OC_A_LSM,                            /**< load state machine */
  OC_KNX_SPAKE,                        /**< spake */
  OC_KNX_K,                            /**< k */
  OC_KNX_FINGERPRINT,                  /**< FINGERPRINT value of loaded contents */
  OC_KNX_IA,                           /**< .well-known / knx / ia */
  OC_KNX,                              /**< .well-known / knx */
  OC_KNX_FP_G,                         /**< FP/G */
  OC_KNX_FP_G_X,                       /**< FP/G/X */
  #ifdef OC_PUBLISHER_TABLE            /** read the notes above on the enum order! */
  OC_KNX_FP_P,                         /**< FP/P */
  OC_KNX_FP_P_X,                       /**< FP/P/X */
  #endif
  OC_KNX_FP_R,                         /**< FP/R */
  OC_KNX_FP_R_X,                       /**< FP/R/X */
  OC_KNX_P,                            /**< P */
  OC_KNX_F,                            /**< f */
  OC_KNX_F_X,                          /**< f/X */
  OC_KNX_SWU_PROTOCOL,                 /**< software update protocol */
  OC_KNX_SWU_HWREF,                    /**< swu hwref */
  OC_KNX_SWU_METHOD,                   /**< swu method */
  OC_KNX_SWU_LASTUPDATE,               /**< swu last update */
  OC_KNX_SWU_RESULT,                   /**< swu result */
  OC_KNX_SWU_STATE,                    /**< swu state */
  OC_KNX_SWU_UPDATE,                   /**< swu update */
  OC_KNX_SWU_PKGV,                     /**< swu package version */
  OC_KNX_SWU_PKGCMD,                   /**< swu package command , a/swu*/
  OC_KNX_SWU_PKGBYTES,                 /**< swu package bytes*/
  OC_KNX_SWU_PKGNAMES,                 /**< swu package names*/
  OC_KNX_SWU,                          /**< swu top level */
  OC_KNX_SUB,                          /**< delete all device subscriptions */
  OC_KNX_AUTH_O_REPLWDO,               /**< oscore replay window*/
  OC_KNX_AUTH_O_OSNDELAY,              /**< oscore osn delay*/
  OC_KNX_AUTH_O,                       /**< auth/o oscore functional block properties list*/
  OC_KNX_AUTH_AT,                      /**< auth/at resource listing auth/at/X */
  OC_KNX_AUTH_AT_X,                    /**< auth/at/X resources */
  OC_KNX_AUTH,                         /**< auth list all sub resources */
  WELLKNOWNCORE,                       /**< well-known/core resource, is the last resource in the list  */
} oc_core_resource_t;

#define OC_NUM_CORE_RESOURCES (1 + WELLKNOWNCORE) // number of core resources, note that first resource index is "0" 

typedef struct oc_resource oc_resource_t;

/**
 * @brief request information structure
 *
 */
typedef struct oc_request_t 
{
  oc_endpoint_t* origin;               /**< origin (endpoint) of the request */
  const oc_resource_t* resource;       /**< addressed target resource */
  const char* query;                   /**< query (as string) */
  size_t query_len;                    /**< query length */
  const char* uri_path;                /**< path (as string) */
  size_t uri_path_len;                 /**< path length */
  oc_rep_t* request_payload;           /**< request payload as structured CBOR (linked list) objects */
  const uint8_t* _payload;             /**< request payload as unstructured BYTE stream */
  size_t _payload_len;                 /**< payload size */
  oc_content_format_t content_format;  /**< content format (of the payload in the request) */
  oc_content_format_t  accept;         /**< accept header, e.g. the format to be returned on the request */
  oc_response_t* response;             /**< pointer to the response */
  coap_method_t request_method;        /**< the request (CoAP) method */
} oc_request_t;

/**
 * @brief request callback, containing
 * - the request,
 * - the interface mask, specified on a (application/core) resource for the corresponding request method (GET, ...)
 * - user data defined by the resource callbacks (if present)
 *
 */
typedef void (*oc_request_callback_t)(oc_request_t*, oc_interface_mask_t, void*);

/**
 * @brief request handler type, including per handler a scope, interface and user data
 *
 * - for the resource, per handler an individual caller acl mask and interface mask
 * - user data , handed over per call (if previously defined on application setup) 
 *
 */
typedef struct oc_request_handler {
  oc_request_callback_t cb;
  void* user_data;
  oc_acl_mask_t acl_scope_mask;	       
  oc_interface_mask_t interface_mask;
} oc_request_handler_t;

/**
 * @brief set properties callback
 *
 */
typedef bool (*oc_set_properties_cb_t)(oc_resource_t*, oc_rep_t*, void*);

/**
 * @brief get properties callback
 *
 */
typedef void (*oc_get_properties_cb_t)(oc_resource_t*, oc_interface_mask_t, void*);

/**
 * @brief properties callback structure
 *
 */
typedef struct oc_properties_cb_t {
  union {
    oc_set_properties_cb_t set_props;
    oc_get_properties_cb_t get_props;
  } cb;
  void* user_data;
} oc_properties_cb_t;

/**
 * @brief resource structure for a resource's (in RAM) modifiable data at runtime 
 * @note data MUST be RAM allocated, even it is part of compiled stack resources (and is of only one byte) 
 *        - for application resources (/p/1/...) it is allocated from HEAP -> oc_new_resource  
 *				- for stack resources (a/lsm, ...) it is allocated from RAM -> core_resource_well_known_core and others 
 *
 */
typedef struct oc_resource_data_t {
  uint8_t num_observers; // amount of observers
} oc_resource_data_t;

/**
 * @brief resource structure
 * @note not defined with typedef directly, done on top of file 
 *
 */
struct oc_resource {
  const struct oc_resource* next;       /**< link to the next resource; static core links are const and application links are assigned at runtime */
  oc_string_t uri;                      /**< resource path (e.g. '/p/lsab/soo') */
  oc_string_array_t types;              /**< resource type array (for a DPA such as 'urn:knx:dpa.0.58' -> dev/da, for an FB such as 'fb.0' -> dev/) */
  oc_string_t dpt;                      /**< resource datapoint type */
  oc_content_format_t content_type[2];  /**< resource content types that will be supported (max two, first mandatory, second optional) */
  oc_resource_properties_t properties;  /**< resource properties (e.g 'discoverable' - bit mask) */
  oc_request_handler_t get_handler;     /**< callback for GET */
  oc_request_handler_t put_handler;     /**< callback for PUT */
  oc_request_handler_t post_handler;    /**< callback for POST */
  oc_request_handler_t delete_handler;  /**< callback for DELETE */
  oc_properties_cb_t get_properties;    /**< callback for get properties */
  oc_properties_cb_t set_properties;    /**< callback for set properties */
  uint16_t observe_period_seconds;      /**< observe period in seconds  */
  uint32_t fb_data;                     /**< compressed FB data* (see extra details) */
  bool is_const;                        /**< resource is precompiled (core = true, application = always false, will be dynamically allocated) */
  oc_resource_data_t* runtime_data;     /**< for an endpoint its modifiable data AT RUNTIME (which one, see resource type) */
};

/*
 * info is encoded PER resource
 * - the FB number (hi 16 bit) the resource belongs to
 * - the FB instance (mid 8 bit) the resource belongs to
 * - the to this FB instance belonging datapoints (low 8 bit), encoded on any resource (there is no parent FB container available in the stack) 
 *
 * init with 0 means instance = 0 = default = only one FB instance present
 */

// defined to safe space since only the next is of interest 
typedef struct oc_resource_dummy_s {
  struct oc_resource* next;            /**< next resource */
} oc_resource_dummy_t;


/**
 * @brief callback return values
 *
 */
typedef enum {
  OC_EVENT_DONE = 0,                   /**< callback is executed, will be deleted (don't call again) */
  OC_EVENT_CONTINUE                    /**< callback is executed, will be NOT deleted, continues, restart timer and wait for next call */
} oc_event_callback_retval_t;

typedef oc_event_callback_retval_t(*oc_trigger_t)(void*);

/**
 * @brief event callback
 *
 */
typedef struct oc_event_callback_s 
{
  struct oc_event_callback_s* next;    /**< next callback */
  struct oc_etimer timer;              /**< timer */
  oc_trigger_t callback;               /**< callback to be invoked */
  void* data;                          /**< data for the callback */
} oc_event_callback_t;

/**
 * @brief initialize the resource implementation handler
 *
 */
void oc_ri_init(void);

/**
 * @brief shut down the resource implementation handler
 *
 */
void oc_ri_shutdown(void);

/**
 * @brief add timed event callback
 *
 * @param cb_data the timed event callback info
 * @param event_callback the callback
 * @param ticks time in ticks
 */
void oc_ri_add_timed_event_callback_ticks(void* cb_data, oc_trigger_t event_callback, oc_clock_time_t ticks);

/**
 * @brief add timed event callback in seconds
 *
 * @param cb_data the timed event callback info
 * @param event_callback the callback
 * @param seconds time in seconds
 */
#define oc_ri_add_timed_event_callback_seconds(cb_data, event_callback, seconds)  \
do {                                                                              \
          oc_ri_add_timed_event_callback_ticks(cb_data, event_callback,           \
          (oc_clock_time_t)(seconds) * (oc_clock_time_t)OC_CLOCK_SECOND);         \
} while (0)

/**
 * @brief remove the timed event callback
 *
 * @param cb_data the timed event callback info
 * @param event_callback the callback
 */
void oc_ri_remove_timed_event_callback(void* cb_data, oc_trigger_t event_callback);

/**
 * @brief convert the (internal) status code to coap status as integer
 *
 * @param key the application level key of the code
 * @return int the CoAP status code
 */
int oc_status_code(oc_status_t key);

/**
 * @brief checks if the accept header is correct
 *
 * @note if no accept header is present in the request, this check also passes
 *       with true by using the default response format (KNX IoT specification clause 2.2.4)
 *
 * @param request the request
 * @param accept the content type of the resource
 *
 * @return true content type is ok
 * @return false content type is not ok => response payload is prepared with BAD REQUEST, NO CONTENT, NO PAYLOAD
 */
bool oc_accept_header_is_ok(const oc_request_t* request, oc_content_format_t accept);

/**
 * @brief retrieve the application resource that fits to the given uri
 *
 * @param resource_path the resource path
 * @param resource_path_len the length of the resource path
 * @return oc_resource_t* the resource structure or NULL (request was NULL, request len was 0 or no resource found)
 */
const oc_resource_t* oc_ri_get_app_resource_by_resource_path(const char* resource_path, size_t resource_path_len);

/**
 * @brief retrieve list root node of application resources (excluding device core resources)
 *
 * @return oc_resource_t* the resource list
 */
oc_resource_t* oc_ri_get_app_resources(void);

#ifdef OC_SERVER
/**
 * @brief allocate a resource structure
 *
 * @return oc_resource_t*
 */
oc_resource_t* oc_ri_alloc_resource(void);

/**
 * @brief allocate a resource structure
 *
 * @return oc_resource_t*
 */
oc_resource_data_t* oc_ri_alloc_resource_data(void);

/**
 * @brief add resource to the system
 *
 * @param resource the resource to be added to the list of application resources
 * @return true success
 * @return false failure
 */
bool oc_ri_add_resource(oc_resource_t* resource);

/**
 * @brief remove the resource from the list of application resources
 *
 * @param resource the resource to be removed from the list of application
 * resources
 * @return true success
 * @return false failure
 */
bool oc_ri_delete_resource(oc_resource_t* resource);
#endif 

/**
 * @brief retrieve the query value at the nth position
 *
 * @param query the input query
 * @param query_len the query length
 * @param key the key
 * @param key_len the length of the key
 * @param value the value belonging to the key
 * @param value_len the length of the value
 * @param n the position to query
 * @return int the position of the next key value pair in the query or NULL
 */
int oc_ri_get_query_nth_key_value(const char* query, size_t query_len, const char** key, size_t* key_len, const char** value, size_t* value_len, size_t n);

/**
 * @brief retrieve the value of the query parameter "key"
 *
 * @param query the input query
 * @param query_len the query length
 * @param key the wanted key
 * @param value a pointer to the value
 * @return int the length of the value
 */
int oc_ri_get_query_value(const char* query, size_t query_len, const char* key, const char** value);

/**
 * @brief checks if key exist in query
 *
 * @param[in] query the query to inspect
 * @param[in] query_len the length of the query
 * @param[in] key the key to be checked if exists, key is null terminated
 * @return int -1 = not exist, 1 exists
 */
int oc_ri_query_exists(const char* query, size_t query_len, const char* key);

/**
 * @brief check if the nth key exists
 *
 * @param query the query to inspect
 * @param query_len the length of the query
 * @param key the key to be checked if exists, key is not null terminated
 * @param key_len the key length
 * @param n
 * @return int
 */
int oc_ri_query_nth_key_exists(const char* query, size_t query_len, const char** key, size_t* key_len, size_t n);

/**
 * @brief dispatches an inbound CoAP request to the handler of the addressed resource and fills
 *        in the response, the server side entry point of the resource interface
 *
 * @note
 *  - called by the CoAP engine (coap_receive) once the request is assembled, applications
 *    never call it
 *  - the resource lookup, the access scope check, the GET/PUT/POST/DELETE handler callback,
 *    observe registration, separate responses and the observer notification happen here
 *  - the response state is allocated here when it is NULL, the response payload is written
 *    into its buffer
 *
 * @param request the inbound coap_packet_t
 * @param response the coap_packet_t the response is written to
 * @param request_state blockwise state holding the request payload, the payload is empty when
 *                      it is NULL
 * @param response_state blockwise state receiving the response payload, allocated when NULL
 * @param block2_size block size for the response
 * @param endpoint endpoint the request was received from
 *
 * @return true when the request reached the handler of a matching resource, false when this
 *         function set an error status on the response itself (bad request, forbidden, not
 *         found, method not allowed, entity too large)
 */
bool oc_ri_invoke_coap_entity_handler(void* request, void* response,
                                      struct oc_blockwise_state_s** request_state,
                                      struct oc_blockwise_state_s** response_state,
                                      uint16_t block2_size,
                                      oc_endpoint_t* endpoint);

/**
 * @brief frame the interface mask in the response, as string in the uri
 * example: full tag if= ":if.i" this function frames ":if.i" (truncated)
 * or "urn:knx:if.i"
 *
 * @param interfaces The interface masks to frame
 * @param truncated 1 = do not frame "urn:knx" in the payload
 * @return int 0 = success
 */
int oc_frame_interfaces_mask_in_response(oc_interface_mask_t interfaces, bool truncated);

/**
 * @brief retrieve the scope mask from the scope name
 *
 * @param acl_scope_name a pointer to a SINGLE, scope name (e.g. 'if.s')
 * @param acl_scope_name_len the access scope name length
 *
 * @note only scope names are used to compare with the input
 *
 * @return oc_acl_mask_t the compacted mask value of the access scopes, also 'OC_ACL_NONE' on no hit
 */
oc_acl_mask_t oc_ri_get_scope_mask(const char* acl_scope_name, size_t acl_scope_name_len);

/**
 * @brief creates a new request from the (old) request by copy it 1:1,
 *        is used internally for handler calls of /k and /p,
 *				 and adds response object to the new request (that includes also the link to the response buffer) 
 *
 * @note
 *  - take care on editing data in the new request (such as in application),
 *    most copied data are pointers, they are a reference to the original source
 *  - adds a new response buffer pointer/size to the new request
 *  - copied endpoint data into new request maybe used in callback handler to access interfaces
 *    or acl scopes
 *
 * @param new_request the original request
 * @param inbound_request the new request
 * @param response_buffer the response buffer for the new request
 * @param response_obj the response object
 *
 */
void oc_ri_new_request_from_inbound_request(oc_request_t* new_request, const oc_request_t* inbound_request, 
                                            oc_response_buffer_t* response_buffer, oc_response_t* response_obj);

void allocate_events(void);

oc_event_callback_retval_t oc_ri_remove_client_cb(void* data);

#ifdef __cplusplus
}
#endif
