# Introduction

This folder contains code examples of how to use the stack.

The intention of the examples is to explain certain aspects of the stack.
e.g., provide information in how to build an KNX IoT Point API device based on the stack.

# Example Applications

The folder contains windows/linux GUI application demos, with several table views and 
interaction buttons. The demo code is defined in *.c and *.cpp files.

- The *.c files hosts KNX data definitions and application handlers.
- The *.cpp files hosts GUI elements and some control logic. 

The files remain separated __on purpose__, even it would be also possible to define all 
content from the *.c files directly as part of the *.cpp files.    
This is to have nearly a full application code skeleton (as c-file) for an embedded device 
(only the **int main (void)** is missing). An complete example of skeleton can be found 
in the c-file template 'knx_iot_application_template' in folder 'template'.

> A proposal how to structure your applications you can find below under 
  'Usage as Application Common Layer'

## Folder '/hems'
The Energy Management System (EMS) [samples](hems/Readme.md) are used to play with the stack and 
KNX based EMS applications (Inverter, Charger, Customer Energy Manager).	

## Folder '/knx'
Common KNX samples of a **Light Switch Actuator Basic** (LSAB), **Light Switch Sensor Basic** (LSSB)
and an **EITT** stack test application. 

### '/knx/eitt'

EITT stack test application, only used to pass the stack certification with the EITT test tool from KNX  
(no use with ETS).

- **knx_iot_virtual_eitt.cpp** 

The EITT test tool requests some predefined settings (serial number, datapoints, clean device,...), 
as defined in the EITT test template. Therefore this (EITT test) application does not support 
command line parameters. Hence this on application startup also a reset (erase code 2) is performed.

For the predefined settings from above see the corresponding *.c file. 
  
### '/knx/lsab' and 'knx/lssb'

KNX Light Switch Actuator Basic and Light Switch Sensor Basic demo applications, used to test the 
stack with the KNX ETS6 tool. 

- **knx_iot_virtual_lsab.c** and **knx_iot_virtual_lssb.c**
- **knx_iot_virtual_lsab.cpp** and **knx_iot_virtual_lssb.cpp**

> The above defined applications supports only their intended datapoints, e.g., for the sensor application only sensor datapoints.
If (for example) you enable for a sensor in ETS also the actuator functionality and assign to the actuator objects also GA's, 
the ETS download of sensor application to the virtual sensor device will fail (this demo behavior may be improved in the future). 

All applications uses KNX standardized datapoints, the corresponding __Functional Block__ and 
__Datapoint Type__ definitions you can find in folder 'apps/knx/data'. 

- 07_20_01 Lighting sensors (LSSB) 
- 07_20_02 Lighting aensors (LSAB)
- 03_07_02 Datapoint Types 

If there are multiple instances of the **same** virtual device run in the **same** network problems will occur (e. g.; 
two developers are testing at the same time their ETS projects with up and running lsab/lssb virtual devices on their computers).
This is due to the fact that at least two virtual devices uses then the same serial number. An ETS instance may then program not 
the intended device from the 'own' installation (it finds all in the network). 
If you run into this problem, you can change the serial number in one test instance (ETS project/ virtual devices). 

1. in the lsab/lssb c-file (for the virtual devices)
2. in the ETS project by updating the certificate (see [ETS6 pages](../../wikis/Home/ETS6))



### 'knx/ets'

Contains a (pre-registered) ETS6 **product** and a (predefined) ETS6 **project**.  

- **knx_iot_virtual_lsxb.knxprod** (product)
- **knx_iot_virtual_lsxb.knxproj** (project)

More details on how to use/edit the product and/or project in ETS6, for this see in [ETS6 pages](../../wikis/Home/ETS6).

## Usage as Application Common Layer

An alternative integration example for the basic KNX IoT demos such as LSAB and LSSB can use the following
application specific files from the apps structure:

### Light Switch Actuator Basic (LSAB)

- **`knx/lsab/knx_iot_virtual_lsab.c`** - Core LSAB functionality and KNX IoT data definitions
- **`knx/lsab/knx_iot_virtual_lsab.cpp`** - GUI demo application for LSAB

### Light Switch Sensor Basic (LSSB)

- **`knx/lssb/knx_iot_virtual_lssb.c`** - Core LSSB functionality and KNX IoT data definitions
- **`knx/lssb/knx_iot_virtual_lssb.cpp`** - GUI demo application for LSSB

## Common KNX IoT Files

- **`knx/knx_iot_virtual_knx.c`** - PUT/GET method implementations
- **`knx/knx_iot_virtual_knx.h`** - Header definitions for KNX methods
  - Used by LSAB, LSSB, and EITT applications
  - Contains common KNX IoT Point API method definitions

## Shared Virtual Demo Files

- **`knx_iot_virtual.c`** - Shared C functions for KNX IoT virtual demo applications
- **`knx_iot_virtual.cpp`** - Shared C++ functions for KNX IoT virtual demo applications
- **`knx_iot_virtual.h`** - Header definitions for shared KNX IoT virtual demo functionality

User applications can leverage these files as a **KNX IoT Point API application common layer**, 
as demonstrated in the `knx_iot_application_template` file.

> Note that the file 'knx_iot_virtual.c/.cpp/.h' are NOT a (library) part of the stack, as a kind of 
  'application' library or API. It hosts only the for the application demos commonly used functionality
  in one place.

### Example of Integration Pattern

```text
User Application
├── Application-specific logic (.c/.cpp)
├── knx_iot_virtual_lsxb (LSAB/LSSB specific declaration of resources)
├── knx_iot_virtual_knx.c/h (KNX IoT PUT/GET method definitions)
├── knx_iot_virtual.c/h (Shared demo functions)
└── KNX IoT Point API Stack (Core)
```

This layered approach allows developers to:

1. Reuse common KNX IoT functionality
2. Build upon proven LSAB/LSSB implementations
3. Leverage shared KNX IoT virtual demo application functions
4. Focus on application-specific logic

# Wireshark

To test runtime communication with Wireshark (Windows) launch a demo application, trigger a telegram (e.g.; press 'SOO' button on LSSB demo),
some **OSCORE** frames shall appear on the ethernet/wifi NIC (usually with a IPv6 multicast address).

By adding the OSCORE 'Security Contexts' in Wireshark (see picture below), the actual payload becomes visible/decrypted. The values you 
can retrieve from the demo application File Dialog, 'List All Tables'. 

![Example](WiresharkOscore.png)