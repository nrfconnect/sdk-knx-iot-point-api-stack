# KNX IoT Client scripts

Python-based client scripts for discovering and commissioning KNX IoT devices on your network, they are based on the KNX IoT Point API specification, supporting mDNS device discovery and secure CoAP communication with OSCORE encryption.

## Features

- **Device Discovery**: Find KNX IoT devices using mDNS/DNS-SD
- **Secure Communication**: OSCORE-protected CoAP requests for reading, writing
- **Resource Discovery**: Query device resources
- **CBOR Decoding**: Encoding/decoding of CBOR payloads

## Prerequisites

- Python 3.11 or higher
- Poetry (Python dependency management)
- Network access to KNX IoT devices

## Installation

### 1) Prerequisites

- Windows 10/11
- Python 3.10 <-> 3.12.3 (3.11 recommended)
- Git (only if cloning the repo)

### 2) Get the project

Clone or copy the repo to the target machine, for example:

```
C:\temp
```

### 3) Install Poetry

Use the Python that you want the project to run with:

```cmd
pip install poetry
```

Configure Poetry to keep the virtual environment inside the repo (required by these scripts):

```cmd
poetry config virtualenvs.in-project true
```

If `poetry install` fails with a permission error on the Poetry cache folder, set a project-local cache:

```cmd
poetry config cache-dir "C:\temp\.poetry-cache"
```

### 4) Install runtime dependencies only

From the repo root:

```cmd
cd C:\temp
poetry install --only main
```

### 5) Start Windows PowerShell

```PS
PS C:\temp> dir


    Directory: C:\temp


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         2/20/2026  10:38 AM                .venv
d-----         2/20/2026  10:35 AM                .vscode
d-----         2/20/2026  10:35 AM                knxiotclient
d-----         2/20/2026  10:35 AM                script
-a----         2/18/2026   2:02 PM             29 .env
-a----         2/18/2026   2:02 PM          90934 poetry.lock
-a----         2/18/2026   2:02 PM            629 pyproject.toml
-a----         2/18/2026   2:02 PM           5159 README.md
-a----         2/18/2026   2:02 PM           1398 SETUP_PV_EV_CEM.md
```

### 6) Start (in PS) the virtual environment

```PS
PS C:\temp> .\.venv\Scripts\Activate.ps1
```

### 7) Start in the virtual environment the scripts

```(knxiotclient-py3.12)
(knxiotclient-py3.12) PS C:\temp> .venv\Scripts\python.exe c:\temp/script/pv.py 00fa10020b00
..
(knxiotclient-py3.12) PS C:\temp> .venv\Scripts\python.exe c:\temp/script/cem.py 00fa10020c00
..
(knxiotclient-py3.12) PS C:\temp> .venv\Scripts\python.exe c:\temp/script/ev.py 00fa10020d00
..
```

### 8) Example Output

```text
======================================================================
KNX IoT: python based commissioning tool for CEM devices
======================================================================
Serial Number: 00fa10020c00

======================================================================
Device Discovery

Looking for device with serial number: 00fa10020c00
Timeout: 3.0 seconds

Device found: 00fa10020c00._knx._udp.local.
  Addresses:
  - 10.3.0.150
  - fe80::2e79:e148:451d:85d0
  - fd3e:f1b0:9b7:101:2cd7:57a2:3888:ba62
  - fd3e:f1b0:9b7:101:d5cf:dd90:8e20:1551
  Port: 53991
Using link-local IPv6 address: fe80::2e79:e148:451d:85d0
======================================================================
request and verify pase parameters
======================================================================
request and verify credential request
======================================================================
confirmV = ok
ms: 90327e27227b32abc473cf1761fe1f78
======================================================================
request and verify verification request
======================================================================
set temp toolkey via /auth/at
delete temp toolkey via /auth/at
set /.well-known/knx/ia 
set /.well-known/knx
set /fp/r 
set /fp/p 
set /fp/g 
set /fp/g 
set /auth/at 
set /auth/at 
======================================================================
commissioning completed
======================================================================
```


## Project Structure

The repository is structured as follows:

| Directory/File          | Description                                                                 |
| ----------------------- | --------------------------------------------------------------------------- |
| `.venv/`                | Python virtual environment (created by bootstrap script)                    |
| `.vscode/`              | VS Code editor configurations                                               |
| `data/`                 | Data directory for security credentials and OSCORE knxiotclient             |
| `knxiotclient/`         | Implementations for mdns, pase and coap handling                            |
| `script/`               | Utility                                                                     |
| `README.md`             | This documentation file                                                     |

## Troubleshooting: no devices discovered

If discovery doesn't find any devices:

1. Verify devices are powered on and connected to the network
2. Check that mDNS/Bonjour is enabled on your network
3. Increase the timeout: `--timeout 10`
4. Check firewall settings (UDP port 5353 for mDNS)

