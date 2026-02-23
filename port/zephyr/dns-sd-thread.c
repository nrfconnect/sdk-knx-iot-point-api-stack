/*
// Copyright (c) 2022 Cascoda Ltd.
// Copyright 2026 NXP
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <ctype.h>

#include "dns-sd.h"
#include "oc_assert.h"
#include "oc_core_res.h"
#include "oc_log.h"

#include <openthread/srp_client.h>
#include <openthread/srp_client_buffers.h>
#include <openthread.h>

#define HOSTNAME_SIZE 64
#define SERIAL_NO_SUBTYPE_SIZE 64
#define SERIAL_NO_LOWERCASE_SIZE 20
#define INSTALLATION_SUBTYPE_SIZE 64
#define SLEEP_PERIOD_RECORD_SIZE 64
#define NUMBER_OF_SUBTYPES 4

#define KNX_SRP_SERVICE_NAME  "_knx._udp"
#define KNX_SRP_PORT          5683  // CoAP KNX IoT

static char sp_text_record[SLEEP_PERIOD_RECORD_SIZE] = "";
static char serial_no_hostname[HOSTNAME_SIZE];
static char serial_no_subtype[SERIAL_NO_SUBTYPE_SIZE];
static char serial_no_lowercase[SERIAL_NO_LOWERCASE_SIZE];
static char installation_subtype[INSTALLATION_SUBTYPE_SIZE];
static otSrpClientBuffersServiceEntry *entry = NULL;
const char *srpSubtype[NUMBER_OF_SUBTYPES] = {NULL};

static bool isInitialized = false;
static bool isUpdating = false;

static void handle_srp_client_callback(otError aError, const otSrpClientHostInfo *aHostInfo,
                                    const otSrpClientService *aServices, const otSrpClientService  *aRemovedServices,
                                    void *aContext)
{
    OT_UNUSED_VARIABLE(aHostInfo);
    OT_UNUSED_VARIABLE(aServices);
    OT_UNUSED_VARIABLE(aRemovedServices);
    OT_UNUSED_VARIABLE(aContext);

    if (aError == OT_ERROR_NONE)
    {
        if (isUpdating == true)
        {
            otInstance * thrInstancePtr = openthread_get_default_instance();

            PRINT("KNX IoT SRP service entry deleted, updating service entry.\n");
            if (entry != NULL)
            {
                otSrpClientAddService(thrInstancePtr, &entry->mService);
            }

            isUpdating = false;
        }
        else
        {
            PRINT("KNX IoT SRP registration successful.\n");
        }
    }
    else
    {
        PRINT("KNX IoT SRP registration failed: %d\n", aError);
    }
}

static void srp_client_cb(const otSockAddr *aServerSockAddr, void *aContext)
{
    PRINT("KNX IoT SRP client cb\n");
}

static void knx_set_srp_host(otInstance *thrInstancePtr, char *serial_no)
{
    char *stringBuffer;
    uint16_t size;

    strncpy(serial_no_lowercase, serial_no, 19);
    for (int i = 0; i < strlen(serial_no_lowercase); ++i) {
        /* make sure that the serial number is used in upper case */
        serial_no_lowercase[i] = toupper(serial_no_lowercase[i]);
    }

    /* Set up the hostname as <serial_number>.knx.local */
    char *hostname_format_string = "%s.knx";

    snprintf(serial_no_hostname, sizeof(serial_no_hostname), hostname_format_string,
             serial_no_lowercase);

    /* Enable SRP client auto start */
    otSrpClientEnableAutoStartMode(thrInstancePtr, srp_client_cb, NULL);

    /* Set Hostname */
    otSrpClientSetHostName(thrInstancePtr, serial_no_hostname);

    /* Configure Service */
    if(entry == NULL)
    {
        entry = otSrpClientBuffersAllocateService(thrInstancePtr);
    }

    if(entry == NULL)
    {
        abort_impl();
    }

    /* This function returns a pointer to the string buffer for service name from a service entry */
    stringBuffer = otSrpClientBuffersGetServiceEntryServiceNameString(entry, &size);

    if(strlen(KNX_SRP_SERVICE_NAME) >= size)
    {
        abort_impl();
    }

    /* Copy the service name into the pointer for the buffer */
    strcpy(stringBuffer, KNX_SRP_SERVICE_NAME);

    /* This function returns a pointer to the string buffer for service instance name from a service entry */
    stringBuffer = otSrpClientBuffersGetServiceEntryInstanceNameString(entry, &size);

    if(strlen(serial_no) >= size)
    {
        abort_impl();
    }
    /* Copy the service instance name into the pointer for the buffer */
    strcpy(stringBuffer, serial_no);

    entry->mService.mPort = KNX_SRP_PORT;
    entry->mService.mPriority = 0;
    entry->mService.mWeight = 0;

    entry->mService.mNext = NULL;

    /* Register Service */
    otSrpClientSetCallback(thrInstancePtr, handle_srp_client_callback, NULL);
    otSrpClientEnableAutoHostAddress(thrInstancePtr);
}

static void knx_set_static_subtypes(void)
{
    /* Set up the subtype for the serial number
       --subtype=_01cafe1234._sub._knx._udp */
    char *serial_format_string = "_%s";
    snprintf(serial_no_subtype, sizeof(serial_no_subtype), serial_format_string,
             serial_no_lowercase);

    /* Set SRP subtype for serial number */
    srpSubtype[1] = serial_no_subtype;
}

static void knx_set_dynamic_subtypes(uint32_t iid, uint32_t ia, bool pm)
{
    /* Set up the subtype for
       --subtype=_ia{installationid}-{ia}._sub._knx._udp */
    char *installation_format_string = "_ia%x-%x";
    snprintf(installation_subtype, sizeof(installation_subtype),
             installation_format_string, iid, ia);

    /* Set SRP subtype for installation */
    srpSubtype[0] = installation_subtype;

    /* Set up the subtype for programming mode
       --subtype=_pm._sub._knx._udp */
    char *pm_subtype = "_pm";

    /* Set SRP subtype for programming mode */
    if (pm == true)
    {
        srpSubtype[2] = pm_subtype;
    }
    else
    {
        srpSubtype[2] = NULL;
    }
}

int knx_publish_service(char *serial_no, uint64_t iid, uint16_t ia, bool pm)
{
    otInstance * thrInstancePtr = openthread_get_default_instance();
    oc_device_info_t *device = oc_core_get_device_info();

    (void)serial_no;
    (void)iid;
    (void)ia;
    (void)pm;

#ifdef OC_DNS_SD
    if (!otIp6IsEnabled(thrInstancePtr) || (device == NULL))
    {
        PRINT("Thread link is not yet up!\r\n");
        return -1;
    }

    /* Setting the SRP Host name, allocating resources and calling SRP auto start should be done only on first call */
    if (isInitialized == false)
    {
        /* Set SRP Client Host name and */
        knx_set_srp_host(thrInstancePtr, oc_string(device->serialnumber));

        /* Set SRP static subtypes */
        knx_set_static_subtypes();
    }

    /* Set or update subtypes */
    knx_set_dynamic_subtypes(device->iid, device->ia, device->pm);

    /* srpSubtype are populated with static or dynamic entries */
    entry->mService.mSubTypeLabels = srpSubtype;

    if (isInitialized == true)
    {
        const otSrpClientService *service = otSrpClientGetServices(thrInstancePtr);

        while (service != NULL)
        {
            if (!strcmp(service->mInstanceName, oc_string(device->serialnumber)) && !strcmp(service->mName, KNX_SRP_SERVICE_NAME))
            {
                break;
            }
            service = service->mNext;
        }

        if (service != NULL)
        {
            otSrpClientRemoveService(thrInstancePtr, (otSrpClientService *) service);
            isUpdating = true;
        }
    }
    else
    {
        otSrpClientAddService(thrInstancePtr, &entry->mService);
    }

    if (isInitialized == false)
    {
        isInitialized = true;
    }
#endif /* OC_DNS_SD */
    return 0;
}

uint16_t knx_get_used_port(void)
{
  return KNX_SRP_PORT;
}

void knx_service_sleep_period(int sp)
{
  if (sp)
    // string includes "SP=xx"
    (void)sprintf(sp_text_record, "SP=%d", sp);
  else
    // empty the string (maybe it was set to SP=xxx before)
    memset(sp_text_record, 0, sizeof(sp_text_record));
}

void knx_stop_mdns(void)
{
    /* To adapt with new used MDNS */
}