# Introduction

This folder contains the Energy Management System (EMS) demo apps. 

The use case is to charge an e-car with a power of 4 kW DC, moreover a user can decide 
for two operation modes.

- In **Sun** mode the e-car is charged exclusively with 'green' solar energy, if the available solar 
  power drops below the threshold of 4 kW (e.g.; cloudy weather) the charging of the e-car is paused.
- In **Mix** mode the charging will never be stopped unless the e-car is fully charged. 
  Hence the charged energy is a mix of solar energy and grid energy. In worst case all energy is 
  retrieved from the grid (e.g.; during night), in best case all energy is 'green' solar energy.   

The charging mode can be set by the user on the Customer Energy Manager (CEM).The below picture 
illustrates the use case.

![Concept](pictures/concept.png)

The following functionalities are involved in this demo use case. 

1. Inverter (provides solar energy)
2. Customer Energy Manager (manages energy) 
3. Charger (consumes energy)

> Note that the grid energy as such is not modelled in this demo. For simplification it is assumed 
  that grid energy is (always) available. 

The above defined three functionalities can be shared amongst several (end) devices. Examples:

- The CEM is a standalone end device.
- The CEM functionality is part of another end device, such a stationary battery.
- The CEM functionality is not part of any end device, it is part of a 'controller logic' on a higher 
  automation level (see below 'Vertical Integration').

This demo covers a simple installation and a unambiguous EMS functionality at runtime, for example 
the inverter functionality runs in an own device. 

> The inverter 'PowerDC' output datapoint maps 1:1 to the counterpart CEM input datapoint. 

Hence this, an individual device configuration by a user is not needed. More complex installations/scenarios
such as to handle two independent charger devices by the CEM are not considered. 

- user channel assignment, which channel of the same 'charger' functionality operates with what other channel  
- user parameter adjustment for a specific charger channel

# References
All applications uses KNX standardized datapoints, the corresponding __Functional Block__ and 
__Datapoint Type__ definitions you can find in folder 'apps/hems/data'. 

- 07_80 Introduction 
- 07_80_01 Photovoltaics (Inverter, Battery) 
- 07_80_02 HVAC for EMS (Heat Pump, Domestic Hot Water, Buffer)
- 07_80_03 eMoblity (Charger)
- 03_07_02 Datapoint Types 

# 1. Inverter

The inverter demo represents an own end device with an *inverter* functionality from 07_80_01. 

> The demo implements a 'PowerDC' output datapoint from the Functional Block 'FB PV Inverter Control', 
  reflecting the sun beam radiation. It is represented by a slider, which allows the user to 'simulate'
  the present DC power from 0 to 10 kW in steps of 1 kW.

# 2. Customer Energy Manager

The customer energy manager demo represents an own end device with a *cem** functionality. 

> The demo application implements
  a counterpart input datapoint for the output 'PowerDC' datapoint of the inverter.
- a counterpart output datapoint for the input 'ActivePowerLimit' datapoint of the charger 
- a sun/mix mode operation setting

# 3. Charger

The charger demo represents an own end device with a *charger** functionality from 07_80_03. 

> The demo implements an 'ActivePowerLimit' input datapoint from the Functional Block 'EVSE AC', 
  reflecting the charging DC power consumption in kW from the e-car. 

# Details 

## Application, Datapoints

In this demo used device serial numbers (SN's) are arbitrary. The EMS functionality 
(aka device applications) is part of the ex-factory device, this also includes the datapoints. 
  
**Inverter**
-  url: '/p/inverter', if.o output, transmit (sends solar power value), 
   datapoint type IEEE 754 single float (KNX datapoint type (DPT) 14.056, see 03/07/02)  
   
**Customer Energy Manager**
-  url: '/p/inverter', if.i input, write (receives solar power value),
   datapoint type IEEE 754 single float (KNX datapoint type (DPT) 14.056, see 03/07/02) 

-  url: '/p/charger', if.o output, transmit (sends charger value),
   datapoint type IEEE 754 single float (KNX datapoint type (DPT) 14.056, see 03/07/02) 
  
**Charger**
-  url: '/p/charger', if.i input, write (receives charger value),
   datapoint type IEEE 754 single float (KNX datapoint type (DPT) 14.056, see 03/07/02) 

## Communication 

KNX IoT devices support two communication patterns, both patterns can operate at runtime
standalone or in parallel (in the latter case it is the operator/installer responsibility
to ensure data validity, such as when writing values from two independent sources).

### Horizontal Interworking

- devices communicate via **s-mode** group communication directly with other devices by using group objects and group addresses
- over a fix endpoint (s-mode messaging path)
- all devices together composes the functionality of an individual installation
- commissioned by ETS, a catalog entry is need for a device, to be created by means of the KNX Manufacturer Tool 

### Vertical Integration

- devices communicate via **pub/sub** communication with a superordinate automation level
  (CoAP subscription and notification mechanism [CoAP RFC7641](https://www.rfc-editor.org/rfc/rfc7641.html))
- over several endpoints (a vendor need to support this for each relevant datapoint)
- commissioned by a vendor client 

The picture below demonstrate this. 

![Concept](pictures/communication-pattern.png)

## Commissioning

For both patterns from above the commission procedures are described as part of the KNX IoT 
specification 03/10/05. 

Energy Management System (EMS) specific [sample scripts](client/knxiotclient/Readme.md) have been foreseen, they can be seen as an alternative to ETS (commissioning by).

Some device commissioning steps are not needed in case of **ONLY** having a 'Vertical Integration' of devices,
this is marked with 'optional'. The overall procedure contains of the following main steps. 

1. Device Discovery 
- (a) add/scan in client the target device certificate (such as a QR Code) 
- (b) resolve device IPv6 unicast address and port by serial number (CoAP multicast/mDNS discovery)
- (c) retrieve device functional block information (CoAP unicast discovery) 
2. Device Preparation 
- (a) initial onboarding via device certificate (well-known/knx/spake, SPAKE2+) 
- (b) check and set individual address (well-known/knx/ia) 
   > optional (not used at runtime on 'Vertical Integration') 
- (c) check and reset device programming mode (dev/pm)
   > optional (not needed on 'Vertical Integration')
- (d) check manufacturer id (dev/mid) 
   > optional (if not writing any application specific parameter)
- (e) check hardware type (dev/hwt)
   > optional (if not writing any application specific parameter)
- (f) reset target device (well-known/knx)
   > optional (vendor application specific)
3. Device Download
- (a) check and set the load state machine (a/lsm)
- (b) write Group Object table entries
   > optional (additional settings not needed on 'Vertical Integration')
- (c) write Recipient table entries
   > optional (not needed on 'Vertical Integration') 
- (d) write Publisher table entries
   > optional (not needed on 'Vertical Integration')
- (e) write Access Token entries
- (f) write parameter values
   > optional (vendor specific, depends on device application) 
- (g) check and close the load state machine (a/lsm)
4. Device Finishing
- (a) read fingerprint and store in client (well-known/knx/f)
   > optional (not needed on 'Vertical Integration')  
- (b) restart device (well-known/knx)
   > optional (vendor specific, depends on device application)
