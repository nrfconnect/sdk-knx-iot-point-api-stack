/*
 * Copyright (c) 2022 Cascoda Ltd.
 * Copyright (c) 2026 NXP
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

/**
 * @file
 * @brief KNX IoT DNS-SD over Thread, implemented with the OpenThread SRP client.
 *
 * Shared by the Zephyr and the ESP-IDF port. The platform differences are the OpenThread
 * instance, the OpenThread API lock and the bound unicast port, see the blocks below the
 * includes.
 *
 * On Thread the device does not run an mDNS responder. It registers its
 * service with the Border Router's SRP server (unicast DNS Update) and the
 * Border Router's advertising proxy publishes it as mDNS on the backbone
 * link. This file keeps the externally visible behaviour identical to the
 * socket port (port/dns-sd_mdns.c):
 *
 *   - service _knx._udp, instance <sn>, host knx-<sn>, port = the UDP port
 *     the KNX unicast socket is actually bound to
 *   - subtypes _<sn>, _ia<iid>-<ia> and, while in programming mode, _pm
 *   - TXT record: "SP=<seconds>" when a sleep period is set, otherwise an
 *     empty TXT record (RFC 6763 clause 6.1; the SRP client emits the single
 *     zero byte itself when no entries are given)
 *   - knx_dns_sd_set_sleep_period() re-publishes immediately
 *   - knx_dns_sd_stop() deregisters host and service at the server, the SRP
 *     equivalent of the mDNS goodbye; a later update re-registers
 *   - an update with unchanged values leaves the registration alone, the
 *     socket port sends no goodbye then either
 *
 * The service is registered only while the device has a routable address,
 * one of the addresses the SRP client registers (preferred, not link-local,
 * not mesh-local). An address that goes while the device stays attached
 * withdraws the registration, the server can be reached then. A detach
 * changes nothing: The SRP client pauses and resumes by itself, and the
 * server keeps the registration for its lease. The registration follows as
 * soon as a routable address appears.
 *
 * SRP forbids modifying a service entry while it is in the client's list, so
 * changes are staged in `pending` and applied when the entry is out of the
 * list. All OpenThread API calls from the KNX stack thread run under the
 * OpenThread API mutex; the SRP callback already runs on the OpenThread
 * thread with that mutex held. The state callback thread_state_changed()
 * runs there the same way.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "port/dns-sd.h"
#include "port/oc_log.h"

#include <openthread/dns.h>
#include <openthread/instance.h>
#include <openthread/ip6.h>
#include <openthread/srp_client.h>
#include <openthread/srp_client_buffers.h>
#include <openthread/thread.h>

#include "api/oc_main.h"

#if defined(__ZEPHYR__)
/* Zephyr: The OpenThread module of Zephyr owns the instance and the API mutex, the bound
 * port comes from the OpenThread connectivity backend of the Zephyr port. */
#include <openthread.h>
#include "port/zephyr/connectivity_thread.h"

static inline otInstance* openthread_instance(void)
{
    return openthread_get_default_instance();
}

static inline void openthread_lock(void)
{
    openthread_mutex_lock();
}

static inline void openthread_unlock(void)
{
    openthread_mutex_unlock();
}

static inline uint16_t knx_unicast_port(void)
{
    return oc_connectivity_thread_get_port();
}
#elif defined(ESP_PLATFORM)
/* ESP-IDF: The OpenThread component owns the instance and the API lock, the bound port comes
 * from the lwIP connectivity backend, which serves the OpenThread esp_netif too. */
#include "esp_openthread.h"
#include "esp_openthread_lock.h"
#include "freertos/FreeRTOS.h"
#include "port/freertos_esp32/connectivity_lwip.h"

static inline otInstance* openthread_instance(void)
{
    return esp_openthread_get_instance();
}

static inline void openthread_lock(void)
{
    (void)esp_openthread_lock_acquire(portMAX_DELAY);
}

static inline void openthread_unlock(void)
{
    esp_openthread_lock_release();
}

static inline uint16_t knx_unicast_port(void)
{
    return knx_connectivity_lwip_get_port();
}
#else
#error "port/dns-sd_srp.c needs an OpenThread platform, Zephyr or ESP-IDF."
#endif

#define KNX_SRP_SERVICE_NAME "_knx._udp"

/* subtype labels: "_" + serial number, "_ia" + iid + "-" + ia, oc_knx.h */
#define SUBTYPE_SN_SIZE (1 + SN_STR_LEN_MAX + 1)
#define SUBTYPE_IA_SIZE (3 + IID_STR_LEN_MAX + 1 + IA_STR_LEN_MAX + 1)
/* "SP=" + up to 5 decimal digits */
#define SP_VALUE_SIZE 8

/** Values the service should advertise; written by the KNX thread, applied
 *  to the SRP entry only while the entry is not in the client's list. */
typedef struct
{
    uint64_t iid;
    uint16_t ia;
    bool pm;
    uint16_t sp;
} knx_srp_values_t;

static otSrpClientBuffersServiceEntry *entry = NULL;  /**< SRP service entry, allocated once */
static char hostname[HNAME_MAX_SIZE + 1];             /**< host name label handed to SRP, domain appended by SRP */
static char pending_hostname[HNAME_MAX_SIZE + 1];     /**< most recent device host name, taken over once SRP released hostname */
static char subtype_sn[SUBTYPE_SN_SIZE];              /**< "_<sn>" */
static char subtype_ia[SUBTYPE_IA_SIZE];              /**< "_ia<iid>-<ia>" */
static const char *subtypes[4];                       /**< NULL-terminated label array for the entry */
static char sp_value[SP_VALUE_SIZE];                  /**< "<seconds>" for the SP TXT entry */
static otDnsTxtEntry txt_sp;                          /**< key "SP", value sp_value */

static knx_srp_values_t pending;   /**< most recent values requested by the stack */
static bool reapply = false;       /**< pending values must still be applied to the entry */
static bool stopped = true;        /**< knx_dns_sd_stop() called, nothing should be registered */

/* ---------------------------------------------------------------- helpers */

static bool entry_in_list(otInstance *inst)
{
    for (const otSrpClientService *s = otSrpClientGetServices(inst); s != NULL; s = s->mNext)
    {
        if (s == &entry->mService)
        {
            return true;
        }
    }
    return false;
}

/** Copy `pending` into the SRP entry. Only valid while the entry is not in the list. */
static void apply_pending(void)
{
    (void)snprintf(subtype_ia, sizeof(subtype_ia), "_ia%llx-%x", (unsigned long long)pending.iid, pending.ia);

    subtypes[0] = subtype_ia;
    subtypes[1] = subtype_sn;
    subtypes[2] = pending.pm ? "_pm" : NULL;
    subtypes[3] = NULL;
    entry->mService.mSubTypeLabels = subtypes;

    if (pending.sp != 0)
    {
        (void)snprintf(sp_value, sizeof(sp_value), "%u", (unsigned)pending.sp);
        txt_sp.mKey = "SP";
        txt_sp.mValue = (const uint8_t *)sp_value;
        txt_sp.mValueLength = (uint16_t)strlen(sp_value);
        entry->mService.mTxtEntries = &txt_sp;
        entry->mService.mNumTxtEntries = 1;
    }
    else
    {
        /* no entries: the SRP client appends the mandatory empty TXT record */
        entry->mService.mTxtEntries = NULL;
        entry->mService.mNumTxtEntries = 0;
    }

    entry->mService.mPort = knx_unicast_port();
    entry->mService.mPriority = 0;
    entry->mService.mWeight = 0;
    entry->mService.mNext = NULL;

    reapply = false;
}

/** Make sure the SRP client knows the host name; false when the host is
 *  still being removed and the caller must wait for the callback. */
static bool ensure_host(otInstance *inst)
{
    const otSrpClientHostInfo *host = otSrpClientGetHostInfo(inst);

    /*
      the SRP host state alone tells whether the host name is in use, no own flag needed:
      - otSrpClientSetHostName() moves the host from REMOVED to TO_ADD (OpenThread srp_client.cpp, Client::SetHostName)
      - knx_dns_sd_stop() moves it to TO_REMOVE / REMOVING, and to REMOVED once the server confirmed
      so any state but REMOVED means named: registered or on the way (true), or still being removed (false, wait for
      the callback)
    */
    if (host->mState != OT_SRP_CLIENT_ITEM_STATE_REMOVED)
    {
        return host->mState != OT_SRP_CLIENT_ITEM_STATE_TO_REMOVE &&
               host->mState != OT_SRP_CLIENT_ITEM_STATE_REMOVING;
    }

    /*
      SRP keeps the pointer to hostname until the host is removed, so a host name changed since (set and store, factory
      reset; knx_dns_sd_stop() first) is taken over only once the removal completed
      - no state check needed here: the return above leaves only REMOVED, so SRP no longer uses hostname
      - copied from pending_hostname, never from device->iot_hostname: this mostly runs in srp_client_callback on the
        OpenThread thread, while the KNX thread may free and reallocate iot_hostname (oc_core_set_device_hostname)
        outside the OpenThread mutex
    */
    memcpy(hostname, pending_hostname, sizeof(hostname));

    otError err = otSrpClientSetHostName(inst, hostname);
    if (err == OT_ERROR_INVALID_STATE)
    {
        /* not expected, the host is REMOVED here; safety net, kept as before */
        return host->mState == OT_SRP_CLIENT_ITEM_STATE_REGISTERED ||
               host->mState == OT_SRP_CLIENT_ITEM_STATE_ADDING ||
               host->mState == OT_SRP_CLIENT_ITEM_STATE_TO_ADD;
    }
    if (err != OT_ERROR_NONE)
    {
        OC_ERR("DNS-SD: SRP set host name failed: %d", err);
        return false;
    }
    (void)otSrpClientEnableAutoHostAddress(inst);
    return true;
}

/** Values the entry carries since its last successful otSrpClientAddService(). */
static knx_srp_values_t applied;

/** Apply pending values and hand the entry to the SRP client. Entry must be out of the list. */
static void add_service(otInstance *inst)
{
    apply_pending();

    otError err = otSrpClientAddService(inst, &entry->mService);
    if (err != OT_ERROR_NONE)
    {
        OC_ERR("DNS-SD: SRP add service failed: %d", err);
        reapply = true;   /* retry on the next callback or update */
        return;
    }
    applied = pending;
    OC_INF("DNS-SD: SRP registering %s.%s port %u ia %x pm %d sp %u", entry->mService.mInstanceName,
           KNX_SRP_SERVICE_NAME, entry->mService.mPort, pending.ia, pending.pm, pending.sp);
}

/** True when the entry carries the pending values and the bound port already. */
static bool pending_is_applied(void)
{
    return (applied.iid == pending.iid) && (applied.ia == pending.ia) &&
           (applied.pm == pending.pm) && (applied.sp == pending.sp) &&
           (entry->mService.mPort == knx_unicast_port());
}

/** Publish `pending`: add the entry if it is free, otherwise start its removal
 *  and let the callback re-add it. Caller holds the OpenThread mutex. */
static void publish(otInstance *inst)
{
    reapply = true;

    if (!ensure_host(inst))
    {
        return;   /* callback continues once the host removal is done */
    }

    if (!entry_in_list(inst))
    {
        add_service(inst);
        return;
    }

    /*
      Nothing to change while the entry is registered or on its way with the same values. SRP
      changes an entry only by removing it and adding it again, and the Border Router announces
      that as a goodbye and a new record on the backbone link. An update with the same values comes
      with every "up" and twice at boot, the addresses follow by themselves
      (otSrpClientEnableAutoHostAddress()). A host name change goes through knx_dns_sd_stop()
      first and does not end here.
    */
    if (pending_is_applied() && (entry->mService.mState != OT_SRP_CLIENT_ITEM_STATE_TO_REMOVE) &&
        (entry->mService.mState != OT_SRP_CLIENT_ITEM_STATE_REMOVING))
    {
        reapply = false;
        return;
    }

    switch (entry->mService.mState)
    {
    case OT_SRP_CLIENT_ITEM_STATE_REGISTERED:
    case OT_SRP_CLIENT_ITEM_STATE_TO_REFRESH:
    case OT_SRP_CLIENT_ITEM_STATE_REFRESHING:
        (void)otSrpClientRemoveService(inst, &entry->mService);
        break;
    default:
        /* TO_ADD / ADDING: wait for registration, then remove and re-add
         * TO_REMOVE / REMOVING: removal already on its way */
        break;
    }
}

/** The registration waits for a routable address, withdrawn or held back while there is none. */
static bool waiting_for_address = false;

/** A routable address existed at the last check, see thread_state_changed(). */
static bool routable = false;

/** True when the Thread interface has an address the SRP client registers and the LAN can reach.
 *  Such an address is preferred, neither link-local nor mesh-local, the rule of
 *  otSrpClientEnableAutoHostAddress(). */
static bool has_routable_address(otInstance *inst)
{
    const otMeshLocalPrefix *ml_prefix = otThreadGetMeshLocalPrefix(inst);

    for (const otNetifAddress *a = otIp6GetUnicastAddresses(inst); a != NULL; a = a->mNext)
    {
        const uint8_t *bytes = a->mAddress.mFields.m8;

        if (!a->mPreferred || a->mRloc)
        {
            continue;
        }

        /* link-local fe80::/10 */
        if ((bytes[0] == 0xfe) && ((bytes[1] & 0xc0) == 0x80))
        {
            continue;
        }

        if ((ml_prefix != NULL) && (memcmp(bytes, ml_prefix->m8, OT_MESH_LOCAL_PREFIX_SIZE) == 0))
        {
            continue;
        }

        return true;
    }

    return false;
}

/* -------------------------------------------------------------- callbacks */

static void srp_client_callback(otError err, const otSrpClientHostInfo *host, const otSrpClientService *services,
                                const otSrpClientService *removed, void *ctx)
{
    (void)services;
    (void)ctx;
    otInstance *inst = openthread_instance();

    if (err != OT_ERROR_NONE)
    {
        OC_ERR("DNS-SD: SRP update failed: %d", err);
        if (reapply && !stopped && !waiting_for_address && entry_in_list(inst) &&
            (entry->mService.mState == OT_SRP_CLIENT_ITEM_STATE_REMOVING))
        {
            /* the server did not confirm the removal; drop the entry locally and re-add */
            (void)otSrpClientClearService(inst, &entry->mService);
            add_service(inst);
        }
        return;
    }

    for (const otSrpClientService *s = removed; s != NULL; s = s->mNext)
    {
        if (s == &entry->mService)
        {
            OC_INF("DNS-SD: SRP service deregistered.");
        }
    }

    /* nothing to register after a stop by choice or without a routable address */
    if (stopped || waiting_for_address)
    {
        if (host->mState == OT_SRP_CLIENT_ITEM_STATE_REMOVED)
        {
            OC_INF("DNS-SD: SRP host deregistered.");
        }
        return;
    }

    if (reapply)
    {
        publish(inst);   /* host removed -> re-name; entry free -> add; else keep removing */
        return;
    }

    if (entry_in_list(inst) && (entry->mService.mState == OT_SRP_CLIENT_ITEM_STATE_REGISTERED))
    {
        OC_INF("DNS-SD: SRP registration successful.");
    }
}

static void srp_autostart_callback(const otSockAddr *server, void *ctx)
{
    (void)ctx;
    OC_INF("DNS-SD: SRP server %s.", server != NULL ? "found" : "lost");
}

/**
 * OpenThread state callback, runs on the OpenThread thread with the API mutex held.
 *
 * Follows the routable address. It appears: The waiting registration is published. It goes while
 * the device stays attached: The registration is withdrawn, the server can be reached. It goes
 * together with a role change (a detach, or an attach that brings the addresses a moment later):
 * Nothing happens, the SRP client pauses and resumes by itself and the server keeps the
 * registration for its lease.
 */
static void thread_state_changed(otChangedFlags flags, void *ctx)
{
    (void)ctx;
    const otChangedFlags watched = OT_CHANGED_IP6_ADDRESS_ADDED | OT_CHANGED_IP6_ADDRESS_REMOVED |
                                   OT_CHANGED_THREAD_ROLE;

    if ((flags & watched) == 0)
    {
        return;
    }

    otInstance *inst = openthread_instance();
    const bool was_routable = routable;
    routable = has_routable_address(inst);

    if (stopped)
    {
        return;   /* nothing to register after a stop by choice */
    }

    if (routable && waiting_for_address)
    {
        OC_INF("DNS-SD: Routable address available, the SRP registration follows.");
        waiting_for_address = false;
        publish(inst);
        return;
    }

    if (was_routable && !routable && ((flags & OT_CHANGED_THREAD_ROLE) == 0) &&
        (otThreadGetDeviceRole(inst) >= OT_DEVICE_ROLE_CHILD))
    {
        OC_INF("DNS-SD: Routable address gone while attached, the SRP registration is withdrawn.");
        waiting_for_address = true;
        reapply = false;

        otError err = otSrpClientRemoveHostAndServices(inst, false, true);
        if ((err != OT_ERROR_NONE) && (err != OT_ERROR_ALREADY))
        {
            OC_WRN("DNS-SD: SRP deregistration failed: %d", err);
        }
    }
}

/* ------------------------------------------------------------- public API */

int knx_dns_sd_update_service(const oc_device_info_t *device)
{
    otInstance *inst = openthread_instance();

   if (!device || !device->serialnumber)
    {
      OC_WRN("DNS-SD: Invalid (NULL) device or serial number provided, cannot update service.");
      return -1;
    }

   if (!inst)
    {
        OC_WRN("DNS-SD: OpenThread not initialised yet!");
        return -1;
    }

    /*
       The advertisement depends on device data the stack loads from storage during its
       initialisation (see oc_knx_load_device()). Until then nothing is announced and the
       one-time setup below never sees an unset serial number. The registration at the end of
       oc_main_init() is the first one.

     */
    if (!oc_main_initialized())
    {
        OC_DBG("DNS-SD: Device data not loaded yet, the service update is postponed.");
        return 0;
    }

    openthread_lock();

    pending.iid = device->iid;
    pending.ia = device->ia;
    pending.pm = device->pm;
    stopped = false;

    // the device host name CAN BE CHANGED at runtime (therefore we need to set here always)
    // it is a label only, such as "knx-<sn>", the SRP client appends the domain itself
    /*
      copied to pending_hostname, not to hostname:
      - SRP keeps the pointer to hostname until the host is removed, a rename (knx_dns_sd_stop() first) arrives here
        while the old host is still being removed; ensure_host() takes it over once the host is REMOVED
      - copied here under the OpenThread mutex on the KNX thread, so the SRP callback reads a stable copy instead of
        iot_hostname, which the KNX thread may free and reallocate
    */
    (void)snprintf(pending_hostname, sizeof(pending_hostname), "%s", oc_string_checked(device->iot_hostname));

    if (entry == NULL)
    {
        /* One-time setup: The static subtype, the SRP entry, the SRP callbacks and the state
         * callback */
        (void)snprintf(subtype_sn, sizeof(subtype_sn), "_%s", device->serialnumber);

        entry = otSrpClientBuffersAllocateService(inst);
        if (entry == NULL)
        {
            openthread_unlock();
            OC_ERR("DNS-SD: no SRP service buffer available!");
            return -1;
        }
        uint16_t size;
        char *name = otSrpClientBuffersGetServiceEntryServiceNameString(entry, &size);
        (void)snprintf(name, size, "%s", KNX_SRP_SERVICE_NAME);
        name = otSrpClientBuffersGetServiceEntryInstanceNameString(entry, &size);
        (void)snprintf(name, size, "%s", device->serialnumber);

        otSrpClientSetCallback(inst, srp_client_callback, NULL);
        otSrpClientEnableAutoStartMode(inst, srp_autostart_callback, NULL);

        if (otSetStateChangedCallback(inst, thread_state_changed, NULL) != OT_ERROR_NONE)
        {
            OC_ERR("DNS-SD: OpenThread state callback not registered, the SRP registration does "
                   "not follow the routable address!");
        }
    }

    /* Registered only with a routable address, thread_state_changed() publishes once one
     * appears. */
    routable = has_routable_address(inst);
    if (!routable)
    {
        OC_INF("DNS-SD: No routable address yet, the SRP registration waits for one.");
        waiting_for_address = true;
        openthread_unlock();
        return 0;
    }

    waiting_for_address = false;
    publish(inst);

    openthread_unlock();
    return 0;
}

void knx_dns_sd_set_sleep_period(uint16_t sp)
{
    otInstance *inst = openthread_instance();

    openthread_lock();

    pending.sp = sp;
    OC_INF("DNS-SD: sleep period set to %u.", (unsigned)sp);

    /* re-publish at once, like the mDNS port re-announces its TXT record */
    /* Without a routable address the value waits with the registration. */
    if ((entry != NULL) && !stopped && !waiting_for_address && (inst != NULL))
    {
        publish(inst);
    }

    openthread_unlock();
}

uint16_t knx_dns_sd_get_used_port(void)
{
    return knx_unicast_port();
}

void knx_dns_sd_stop(void)
{
    otInstance *inst = openthread_instance();

    openthread_lock();

    stopped = true;
    reapply = false;
    waiting_for_address = false;   /* a stop by choice ends the wait for a routable address */

    if ((inst == NULL) || (entry == NULL))
    {
        openthread_unlock();
        return;
    }

    /* SRP goodbye: remove host and services at the server (key lease kept so
     * the name stays ours), a following update re-registers */
    otError err = otSrpClientRemoveHostAndServices(inst, false, true);
    if ((err != OT_ERROR_NONE) && (err != OT_ERROR_ALREADY))
    {
        OC_WRN("DNS-SD: SRP deregistration failed: %d", err);
    }
    openthread_unlock();
}
