# Building a KNX IoT Application

This guide takes you from a first build to a device that is ready for
certification. It is written for firmware developers who are new to the
KNX IoT Point API stack.

## Contents

1. [Concepts](#1-concepts)
2. [Get started with a demo](#2-get-started-with-a-demo)
3. [Anatomy of an application](#3-anatomy-of-an-application)
4. [Step 1: Give the device an identity](#4-step-1-give-the-device-an-identity)
5. [Step 2: Start the stack](#5-step-2-start-the-stack)
6. [Step 3: Run the event loop](#6-step-3-run-the-event-loop)
7. [Step 4: Add datapoints](#7-step-4-add-datapoints)
8. [Step 5: Send and receive group messages](#8-step-5-send-and-receive-group-messages)
9. [Step 6: React to device management](#9-step-6-react-to-device-management)
10. [Step 7: Support software update](#10-step-7-support-software-update)
11. [Test and certify](#11-test-and-certify)
12. [Checklist](#12-checklist)
13. [API quick reference](#13-api-quick-reference)

## 1. Concepts

A KNX IoT device exposes its application as **datapoints**: CoAP resources
under `/p/...` that hold one value each, such as a switch state or a
temperature. Datapoints are grouped into **functional blocks** defined by
KNX, for example functional block 421 "light switching sensor basic" (LSSB)
with an on/off output and a status input.

Each datapoint plays one role:

- **Output**: a value the device reports, such as a button state.
- **Input**: a command the device receives, such as "switch on".
- **Parameter**: a configuration value set during commissioning.

Devices talk to each other through **group communication** (s-mode): an
output sends its value to a group address, and every input linked to that
address receives it. Which datapoint uses which group address is configured
by a **management client**, typically ETS, during commissioning. The device
stores that configuration in its tables (group object table, recipient table,
publisher table) and in its **volatile device data** (individual address,
installation ID, load state, ...).

Before ETS can configure a device, it **onboards** it with the password from
the device label or QR code. The device proves it knows the password with
SPAKE2+, using a registration record computed in manufacturing.

**What the stack does for you:** CoAP and OSCORE, onboarding and security,
the management resources ETS uses, storing the configuration, discovery, and
routing group messages to your datapoints.

**What you write:** the device identity, the datapoints and their handlers,
the event loop, and the reactions to management actions and software
updates.

## 2. Get started with a demo

The demos repository (`knx-iot-point-api-demos`) contains complete
applications built on the stack. Build and run one before writing your own:

- Linux and Windows: follow `HOW-TO-BUILD.md`. The headless targets
  (`lssb_virtual_headless`, `lsab_virtual_headless`, `uhrs_virtual_headless`)
  run without a GUI; the `*_virtual_gui` targets show the datapoints and
  device state in a window.
- Zephyr boards: follow `HOW-TO-BUILD-ZEPHYR.md` for the LSAB, LSSB and EITT
  apps. An application of your own on Zephyr needs the Zephyr patches in
  `port/zephyr/patches/`: `README.md` there says which ones a board needs.

Then onboard and configure the device with ETS and switch a datapoint. The
KNX IoT documentation site has a walkthrough under "Point API Stack →
Examples".

**Pick a starting point:**

| Demo | Use it as a starting point when... |
| --- | --- |
| `apps/template/knx_iot_application_template.c` | You want a minimal skeleton with an event loop and no datapoints |
| `apps/knx/lssb/` | You build a sensor (outputs) |
| `apps/knx/lsab/` | You build an actuator (inputs that drive outputs) |
| `apps/knx/uhrs/` | You need parameters and many datapoint types |
| `apps/hems/` | You build an energy management device |

The demo helper files `apps/knx_iot_app.c` and `apps/knx_iot_datapoint.c`
are not part of the stack. Copy them into your project and adapt them.

## 3. Anatomy of an application

A complete application has these parts. The following sections build them
one by one.

| Part | Provided by | Section |
| --- | --- | --- |
| Device identity (serial number, manufacturer, SPAKE2+ record) | you | 4 |
| Stack start-up and callbacks | you | 5 |
| Event loop | you | 6 |
| Datapoint registration and handlers | you | 7 |
| Sending values to groups | you | 8 |
| Reset, restart and programming mode reactions | you | 9 |
| Firmware download and update | you | 10 |
| CoAP, security, management resources, storage, discovery | stack | — |

Mandatory pieces, without which the device does not start:

- `init` and `signal_event_loop` in the `oc_handler_t` passed to
  `oc_main_init()`
- the restart callback and both software update callbacks
- `app_get_precalculated_spake_data()`

When the stack's shell commands are built (Zephyr and ESP-IDF with
`CONFIG_KNXIOT_SHELL`, enabled by default when a shell is present), you also
define `app_get_password()` and `knx_iot_get_application_name()`.

## 4. Step 1: Give the device an identity

The device identity is the **permanent device data**: values that identify
the device and never change over its lifetime, plus the SPAKE2+
registration record used for onboarding. The demos keep all of it in one
constant struct per application, `device_permanent_data`, of type
`knx_iot_permanent_device_data_t` (declared in `apps/knx_iot_app.h`). Copy
that pattern.

### Define the permanent device data

From `apps/knx/lsab/knx_iot_lsab.c`:

```c
// SPAKE2+ offline registration record (RFC 9383 sec. 3.2), computed from the device password
static const oc_spake_record_t g_spake_record =
{
  .w0   = { ... },
  .L    = { ... },
  .salt = { ... },
  .it   = 50000,
  .valid = true,
};

const knx_iot_permanent_device_data_t device_permanent_data =
{
  .application_name = "KNX-IoT demo actuator (LSAB)",
  .sn_lower_case    = "00fa10020900",              // serial number, 12 lower-case hex characters
  .hw_type          = "000102030405",              // hardware type, 12 characters, MSB = 00
  .order_number     = "5WG1-LSAB-8",               // product order number
  .mfg_date         = "2020-03-12T23:20:50.52Z",   // manufacturing date, RFC 3339
  .hw_ref           = "0102030405ABCDEF",          // hardware reference for software update
  .mid              = 0x00fa,                      // manufacturer ID
  .hw_ver           = {.major = 0, .minor = 0, .patch = 1},
  .spake_record     = &g_spake_record,             // registration record, see below
};
```

On Zephyr the demos fill the same struct from Kconfig
(`CONFIG_DEVICE_SERIAL_NUMBER`, `CONFIG_DEVICE_HW_TYPE`, ...), so a product
can set the values per build; see `apps/knx/lssb/knx_iot_lssb.c`.

The SPAKE2+ record is referenced through a pointer rather than embedded, so
it can live elsewhere, for example in a protected flash partition.

### Hand it to the stack

`knx_iot_initialize_stack()` in `apps/knx_iot_app.c` passes the struct to the
stack on every boot, after storage is configured and before the stack starts:

```c
oc_core_set_device_sn(device_permanent_data.sn_lower_case);
oc_core_set_device_mid(device_permanent_data.mid);
oc_core_set_device_hwt(device_permanent_data.hw_type);
oc_core_set_device_order_number(device_permanent_data.order_number);
oc_core_set_device_hwv(&device_permanent_data.hw_ver);
oc_core_set_device_mfd(device_permanent_data.mfg_date);
oc_swu_set_hwref(device_permanent_data.hw_ref);
```

The setters keep the **pointers** you pass, not copies, which is why the
struct is a `const` global. Invalid values for the serial number, order
number or hardware reference stop the device, so validate data you read from
OTP or flash first.

The stack fetches the SPAKE2+ record itself during start-up by calling
`app_get_precalculated_spake_data()`, which `apps/knx_iot_app.c` implements
from the same struct:

```c
const oc_spake_record_t* app_get_precalculated_spake_data(void)
{
  return device_permanent_data.spake_record;
}
```

If it returns NULL or a record with `.valid == false`, the stack does not
start.

### Password and registration record

The device never needs the plaintext onboarding password, only the
registration record computed from it. In production, every device gets its
own password and record. Generate them together in manufacturing and print
the password on the device label and in the QR code, formatted as
`KNX:S:<serial number>;P:<password>`. The stack repository contains
`tests/common/tools/gen_spake_record.py` to compute a record from a password,
salt and iteration count. The record in the demos is for development only.

The demos also define `app_get_password()` next to the record; it is used
only to display the password and QR code (shell, GUI), never for
onboarding.

## 5. Step 2: Start the stack

Start-up runs on the thread that will later run the event loop:

```c
int knx_start(void)
{
  // 1. storage: the stack reads its persistent data from here
  oc_storage_config("knx_iot");

  // 2. permanent device data: the oc_core_set_device_*() calls from section 4
  oc_core_set_device_sn(device_permanent_data.sn_lower_case);
  // ...

  // 3. callbacks
  oc_set_restart_cb(my_restart_cb, NULL);                     // mandatory
  oc_set_swu_cb(my_swu_cb, NULL);                             // mandatory
  oc_set_swu_upgrade_cb(my_swu_upgrade_cb, NULL);             // mandatory
  oc_set_factory_presets_cb(my_factory_presets_cb, NULL);     // optional
  oc_set_reset_cb(my_reset_cb, NULL);                         // optional
  oc_set_programming_mode_cb(my_programming_mode_cb, NULL);   // optional
  oc_set_lsm_change_cb(my_lsm_change_cb, NULL);               // optional

  // 4. start
  static const oc_handler_t handler = {
    .init = my_init,                             // mandatory
    .signal_event_loop = my_signal_event_loop,   // mandatory
    .register_resources = my_register_resources, // optional, server builds
    .requests_entry = NULL,                      // optional, client builds
  };
  return oc_main_init(&handler);                 // < 0 on failure
}
```

The `data` pointer you pass with each callback is handed back on every call
for as long as the stack runs. Use static storage or NULL.

### What happens inside `oc_main_init()`

1. The stack checks the mandatory callbacks and sets up security, including
   loading the SPAKE2+ record.
2. It calls your `init()`. Call `oc_core_set_device_res()` here; it creates
   the device tables and starts connectivity. Return `0`, or a negative value
   to abort start-up. `init()` is also the place for a custom host name
   (`oc_core_set_device_hostname()`).
3. It loads the volatile device data from storage: individual address,
   installation ID, fabric ID, load state, firmware and application version,
   host name and fingerprint.
4. It calls `register_resources()`, where you create your datapoints
   (section 7).
5. It joins the multicast groups from the publisher table and refreshes the
   network endpoints.
6. In client builds, it calls `requests_entry()` and starts reading the
   values of group objects configured with "read on init".

`oc_main_init()` returns `0` on success. Calling it a second time has no
effect.

### Volatile device data

Volatile data is written by ETS during commissioning and restored from
storage at start-up. Normally your application only reads it, through
`oc_core_get_device_info()`. When the application has to set a value itself,
use the setter that also stores it:

| Value | Setter |
| --- | --- |
| Individual address, installation ID, fabric ID | `oc_core_set_and_store_device_ia()`, `..._iid()`, `..._fid()` |
| Firmware version | `oc_core_set_and_store_device_fwv()` |
| Application version | `oc_core_set_and_store_device_application_version()` |
| Last software update | `oc_swu_set_last_update()` |
| Host name | `oc_core_set_device_hostname()` |
| Load state | `oc_knx_set_and_store_lsm()` |

`oc_knx_set_and_store_lsm()` only sets and stores the value. A load state
change through ETS also updates multicast groups, the fingerprint and the
DNS-SD record, so leave the load state to ETS in normal operation.

## 6. Step 3: Run the event loop

The stack does not own a thread. Your application calls `oc_main_poll()` in
a loop. `oc_main_poll()` processes everything that is due and returns the
absolute time of the next scheduled event in clock ticks (`OC_CLOCK_SECOND`
ticks per second), or `0` when nothing is scheduled. Between calls the loop
sleeps until that time or until `signal_event_loop()` wakes it:

```c
static bool pending;                             // protected by mutex

void my_signal_event_loop(void)                  // called from any thread
{
  lock(mutex);
  pending = true;
  signal(cond);
  unlock(mutex);
}

void knx_thread(void)
{
  while (running) {
    oc_clock_time_t next_event = oc_main_poll();
    lock(mutex);
    if (!pending) {
      if (next_event == 0) {
        wait(cond, mutex);                                     // nothing scheduled
      } else {
        wait_for(cond, mutex, next_event - oc_clock_time());   // until due or signalled
      }
    }
    pending = false;
    unlock(mutex);
  }
  oc_main_shutdown();
}
```

The `pending` flag keeps a wake-up that arrives while `oc_main_poll()` is
running from being lost.

`signal_event_loop()` is called by the stack from the network receive thread
and from any thread that schedules work, so it must be thread-safe and must
return quickly.

Platform versions of this loop are in the demos:
`apps/template/knx_iot_application_template.c` (Windows, Linux) and
`apps-zephyr/knx_iot_app_zephyr.c` (Zephyr, as its own thread). A GUI
application can instead call `oc_main_poll()` from a periodic UI timer and
leave `signal_event_loop()` empty; everything then runs on the UI thread.

### Threading rule

Call stack functions only from the thread that runs `oc_main_poll()`. All
request handlers and callbacks in this guide already run there, except
`signal_event_loop()`.

Events from other threads, such as a button interrupt or a sensor task, must
be handed over: put the event in a queue or set a flag, call
`signal_event_loop()`, and process it on the stack thread, for example in a
periodic timer callback.

### Timers

```c
static oc_event_callback_retval_t poll_sensor(void* data)
{
  read_sensor_and_send();
  return OC_EVENT_CONTINUE;          // run again; OC_EVENT_DONE for one-shot
}

oc_set_delayed_callback(NULL, poll_sensor, 10);     // every 10 s
```

`oc_remove_delayed_callback(data, cb)` cancels a timer.
`oc_set_delayed_callback_ms()` takes its delay in clock ticks; convert
milliseconds with `ms * OC_CLOCK_SECOND / 1000`.

## 7. Step 4: Add datapoints

### Register a datapoint

Create datapoints in `register_resources()`:

```c
static void register_switch_output(void)
{
  oc_resource_t* res = oc_new_resource("/p/lssb/0/soo", 1);
  if (res == NULL) {
    return;                                                    // path too long or out of memory
  }
  oc_resource_bind_resource_type(res, "urn:knx:dpa.421.61");   // datapoint annotation
  oc_resource_bind_dpt(res, ":dpt.switch");                    // datapoint type
  oc_resource_bind_content_type(res, APPLICATION_CBOR, CONTENT_NONE);
  oc_resource_set_functional_block_data(res, 421, 0, 2);       // FB 421, instance, datapoints in the FB
  oc_resource_set_properties(res, OC_DISCOVERABLE | OC_OBSERVABLE);
  oc_resource_set_request_handler(res, COAP_GET, get_switch, (void*)(uintptr_t)0, OC_ACL_O, OC_IF_O);
  if (!oc_add_resource(res)) {
    // rejected: invalid interface combination or no handler
  }
}
```

Rules for the path and the functional block:

- The path must be shorter than 30 characters. The stack keeps a pointer to
  it, so use a string literal or static storage.
- Set the functional block data on every point that belongs to a functional
  block. Use instance `0` when the device has one instance of the functional
  block (listed as `421`). With several instances, number them from 1
  (listed as `421_1`, `421_2`, ...). Parameters and diagnostic values that
  apply to the whole device do not have to belong to a functional block.
- The annotation (`urn:knx:dpa.<FB>.<datapoint>`) and the datapoint type
  come from the KNX functional block definitions.

`user_data` is passed to the handlers unchanged. A small integer cast
through `uintptr_t` lets one handler serve many channels; the demos use
`(channel << 8) + point`.

`apps/knx_iot_datapoint.c` wraps these calls in
`knx_iot_register_functional_block_datapoint()`.

### Choose interfaces and scopes

The interface and scope of each handler decide who may call it:

| Role | GET handler | PUT handler | Properties |
| --- | --- | --- | --- |
| Output | `OC_ACL_O \| OC_ACL_D`, `OC_IF_O \| OC_IF_D` | none | `OC_DISCOVERABLE \| OC_OBSERVABLE` |
| Input | `OC_ACL_I \| OC_ACL_D`, `OC_IF_I \| OC_IF_D` | `OC_ACL_I`, `OC_IF_I` | `OC_DISCOVERABLE` |
| Parameter | `OC_ACL_P \| OC_ACL_D`, `OC_IF_P \| OC_IF_D` | `OC_ACL_P`, `OC_IF_P` | `OC_DISCOVERABLE \| OC_WRITE_AFFECTS_FP` |
| Diagnostic value (read-only) | `OC_ACL_D`, `OC_IF_D` | none | `OC_DISCOVERABLE` |

Where these rules come from (KNX IoT Point API, chapter 3/10/5, version
1.4.1):

- Every point under `/p` must be readable with the diagnostic interface
  `if.d`. A parameter that ETS writes uses `if.p` for writing, and the `if.p`
  scope grants reading as well, so its GET accepts both.
- A client needs only one of the scopes listed for a method; the masks are
  combined with OR.
- `if.i` and `if.o` must not be combined on one point;
  `oc_add_resource()` rejects that. The specification recommends combining
  `if.i` only with `if.p`, and `if.o` only with `if.d`. An input that ETS may
  also set as a parameter therefore uses `OC_ACL_I | OC_ACL_P` and
  `OC_IF_I | OC_IF_P` on its PUT handler.
- An observable resource needs `OC_IF_O` on its GET handler.

`OC_WRITE_AFFECTS_FP` marks values that belong to the device configuration.
The configuration fingerprint must reflect every setting that changes the
application's behaviour, so set the flag on every such parameter, and not on
diagnostic values. When ETS writes such a value through a POST on `/p`, the
stack updates the fingerprint.

### Write the GET handler

All handlers have this signature:

```c
void handler(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data);
```

A GET handler encodes the value as CBOR with key `1` and prepares the
response:

```c
static void get_switch(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data)
{
  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR)) {
    return;                                    // the stack has prepared 4.00 Bad Request
  }
  oc_rep_begin_root_object();
  oc_rep_i_set_boolean(root, 1, switch_state((uintptr_t)user_data));
  oc_rep_end_root_object();

  if (g_err != CborNoError) {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
  } else {
    oc_prepare_cbor_response(request, OC_STATUS_OK);
  }
}
```

A GET handler must also answer metadata queries: `?m=id`, `value`, `rt`,
`if`, `dpt`, `ga`, `href`, or `*` for all of them. `knx_iot_get_handler()` in
`apps/knx_iot_datapoint.c` implements this for bool, int, float and string
values; use it or extend it for other types.

The stack calls GET handlers internally as well, to build group messages and
observe notifications. Keep them free of side effects.

### Write the PUT handler

The new value arrives as the CBOR item with key `1`:

```c
static void put_switch(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data)
{
  for (const oc_rep_t* rep = request->request_payload; rep; rep = rep->next) {
    if (rep->iname == 1 && rep->type == OC_REP_BOOL) {
      set_relay((uintptr_t)user_data, rep->value.boolean);
      oc_prepare_no_format_response_no_payload(request, OC_STATUS_CHANGED);
      return;
    }
  }
  oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
}
```

`knx_iot_put_handler()` in the demos does the parsing for the common value
types and calls a function of yours with the new value.

Every handler ends with exactly one response call
(`oc_prepare_cbor_response()`, `oc_prepare_no_format_response_no_payload()`,
...) or `oc_ignore_request()`. Answer in the handler itself; do not defer
datapoint responses. A resource without a PUT handler is answered with
4.05 Method Not Allowed by the stack.

### Know where a request comes from

The same handler is called in several situations.
`oc_is_redirected_request_from(request)` tells them apart:

| Return | Situation |
| --- | --- |
| `0` | Group message on `/k`: write or read response (PUT handler), read (GET handler) |
| `1` | Direct access by a client: GET or PUT on `/p/...`, or POST on `/p` |
| `2` | Internal: the stack reads the value for a group send, or delivers a sent value to other datapoints on this device (section 8) |
| `-1` | Internal: the stack builds an observe notification |

### Notify observers

Clients can observe output datapoints. The stack notifies observers after a
direct PUT on `/p/...` and after a successful group send (section 8). After
any other change of an observable value, call
`oc_notify_observers(resource)` yourself.

## 8. Step 5: Send and receive group messages

### Receive

There is nothing extra to do. When ETS links a group address to an input
datapoint, the stack delivers group writes to its PUT handler. Answers to
group reads arrive at the PUT handler too, if the group object has the
"update" and "write" flags.

### Send

When an output value changes, send it to its group:

```c
oc_send_s_mode_mc_or_uc_message(KNX_MULTICAST_SCOPE, "/p/lssb/0/soo", 'w');
```

`KNX_MULTICAST_SCOPE` comes from the build configuration (CMake variable
`KNX_MULTICAST_SCOPE`, Kconfig `CONFIG_KNX_MULTICAST_SCOPE` on Zephyr).

The stack then:

1. Finds the group object for this path and its sending group address, and
   checks that the group object may transmit.
2. Reads the current value through your GET handler.
3. Sends the message to the recipient configured for that group address,
   as multicast or unicast.
4. Delivers the value locally to every datapoint on this device whose group
   object listens to the same group address and may be written. Their PUT
   handlers are called with source `2`.
5. Notifies the observers of the sending datapoint.

The function returns `-1` when the device is not configured yet (load state
not "loaded"), the path is unknown, or no group object may transmit for it.
That is the normal state before commissioning, not an error to report.
Use `'r'` instead of `'w'` to send a group read.

An actuator typically sends its new status from the PUT handler of its
command input. That is allowed. When the send happens during a local
delivery (source `2`), the message still goes out, but the stack does not
deliver it locally a second time.

## 9. Step 6: React to device management

ETS restarts, resets and switches the programming mode of the device. Your
application can react through these callbacks, all registered before
`oc_main_init()`:

| Callback | Called | Typical use |
| --- | --- | --- |
| `oc_set_restart_cb` (mandatory) | When a client requests a restart, after the stack's own restart actions. The device is not rebooted. | Reset runtime values to their defaults |
| `oc_set_factory_presets_cb` | Before a reset deletes stored data | Restore manufacturer defaults |
| `oc_set_reset_cb` | After a reset, with the KNX reset code | Reset application state |
| `oc_set_programming_mode_cb` | When a client changes the programming mode | Switch the programming LED. The callback must call `oc_knx_device_set_programming_mode()` itself. |
| `oc_set_lsm_change_cb` | On every load state event from ETS, including events that keep the state | Enable or disable application behaviour depending on the load state; compare with the previous state yourself |

### Programming mode button

A KNX device has a programming button. ETS uses programming mode to find the
device during commissioning. Toggle it on the stack thread:

```c
oc_knx_device_set_programming_mode(!oc_knx_device_in_programming_mode());
```

## 10. Step 7: Support software update

ETS can download a new firmware image to the device and then ask it to
install the image. The stack handles the protocol; your application stores
and applies the image. Both callbacks are mandatory, also on devices that do
not support updates.

### Receive the image

`oc_set_swu_cb` registers the block callback:

```c
void my_swu_cb(oc_separate_response_t* response, size_t binary_size,
               size_t block_offset, const uint8_t* block_data, size_t block_len, void* data);
```

It is called once per block. `binary_size` is the total image size; later
blocks may pass `0`. For each block:

1. Write the block to the update partition or file. Finish the write inside
   the callback; the stack answers the block when the callback returns.
2. After the last block, verify the image (size, checksum, signature), then
   call `oc_swu_set_package_version()`, `oc_swu_set_package_name()` and
   `oc_swu_set_state(OC_SWU_STATE_DOWNLOADED)`.
3. On an error, call `oc_swu_set_result()` with the matching
   `OC_SWU_RESULT_ERR_*` code and `oc_swu_set_state(OC_SWU_STATE_IDLE)`.

A device without update support rejects every block this way.

### Install the image

`oc_set_swu_upgrade_cb` registers the install callback. It receives a defer
time in seconds. Schedule the installation with `oc_set_delayed_callback()`
so the response to ETS goes out first (at least 2 seconds). When the
installation is done:

```c
oc_core_set_and_store_device_fwv(&new_version);
oc_swu_set_last_update(current_time_rfc3339);    // timestamp of the update
oc_swu_set_result(OC_SWU_RESULT_INIT);
oc_swu_set_state(OC_SWU_STATE_IDLE);
```

If the update reboots into the new image, make these calls on the next boot,
once the new image is confirmed. The firmware version is stored data and
starts at `0.0.0`, so also set it once in manufacturing or on first boot.

`apps/knx_iot_app.c` contains a complete implementation for a file on
Windows and Linux and for the MCUboot secondary slot on Zephyr.

## 11. Test and certify

1. **Commission with ETS.** Onboard the device with its QR code, download a
   project, and check that group messages flow in both directions.
2. **Run the EITT test suite.** EITT is the KNX conformance test tool. The
   demos contain an EITT test application (`apps/knx/eitt/`) that shows the
   datapoints and parameters the test template expects. The KNX IoT
   documentation site explains the setup under "Certification → How to Use
   EITT".
3. **Certify.** The certification process is described on the documentation
   site under "Certification → KNX IoT Certification Process".

## 12. Checklist

- [ ] Own serial number, manufacturer ID, hardware type and order number, in storage that lives as long as the device runs
- [ ] Per-device password and SPAKE2+ record from manufacturing, returned by `app_get_precalculated_spake_data()`
- [ ] Storage configured and permanent data set before `oc_main_init()`
- [ ] `init`, `signal_event_loop`, restart callback and both software update callbacks set
- [ ] `init()` calls `oc_core_set_device_res()` and returns `0`
- [ ] Event loop with a pending flag; stack calls only from the stack thread
- [ ] Every point of a functional block has its functional block data; every point has annotation, datapoint type, interfaces and scopes per the table in section 7; `oc_add_resource()` returned true
- [ ] Every parameter that changes the application's behaviour sets `OC_WRITE_AFFECTS_FP`
- [ ] GET handlers answer metadata queries and have no side effects
- [ ] PUT handlers accept group writes and local deliveries
- [ ] Output changes are sent with `oc_send_s_mode_mc_or_uc_message()`
- [ ] Programming button toggles programming mode
- [ ] Firmware version set in manufacturing and after each update
- [ ] Device commissioned with ETS and tested with EITT

## 13. API quick reference

The headers contain the full function documentation.

| Task | Functions | Header |
| --- | --- | --- |
| Start and run | `oc_main_init`, `oc_main_poll`, `oc_main_shutdown` | `include/oc_api.h` |
| Callbacks | `oc_set_restart_cb`, `oc_set_reset_cb`, `oc_set_factory_presets_cb`, `oc_set_programming_mode_cb`, `oc_set_swu_cb`, `oc_set_swu_upgrade_cb` | `include/oc_api.h` |
| Load state callback and setter | `oc_set_lsm_change_cb`, `oc_knx_set_and_store_lsm` | `include/oc_knx.h` |
| Device data | `oc_core_set_device_*`, `oc_core_set_and_store_device_*`, `oc_core_get_device_info` | `include/oc_core_res.h` |
| Storage | `oc_storage_config` | `port/oc_storage.h` |
| Resources | `oc_new_resource`, `oc_resource_bind_*`, `oc_resource_set_*`, `oc_add_resource` | `include/oc_api.h` |
| Responses | `oc_prepare_cbor_response`, `oc_prepare_no_format_response_no_payload`, `oc_ignore_request`, `oc_accept_header_is_ok` | `include/oc_api.h`, `include/oc_ri.h` |
| Query parameters | `oc_query_value_exists`, `oc_get_query_value`, `oc_iterate_query` | `include/oc_api.h` |
| Observers | `oc_notify_observers` | `include/oc_api.h` |
| Group communication | `oc_send_s_mode_mc_or_uc_message`, `oc_is_redirected_request_from` | `api/oc_knx_client.h` |
| Programming mode | `oc_knx_device_in_programming_mode`, `oc_knx_device_set_programming_mode` | `api/oc_knx_dev.h` |
| Software update | `oc_swu_set_state`, `oc_swu_set_result`, `oc_swu_set_package_*`, `oc_swu_set_last_update`, `oc_swu_set_hwref` | `api/oc_knx_swu.h` |
| Timers | `oc_set_delayed_callback`, `oc_set_delayed_callback_ms`, `oc_remove_delayed_callback` | `include/oc_api.h` |
| SPAKE2+ record | `app_get_precalculated_spake_data` (you implement it) | `include/oc_knx.h` |
