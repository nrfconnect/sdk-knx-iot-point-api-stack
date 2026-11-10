# Licensing

This document describes how license information is expressed in the files of the KNX-IoT Point
API Stack, which rule applies to which files, and the findings and references the rules are based
on.

## Project license

- **The project is licensed under the Apache License 2.0.**
  The root file `LICENSE.md` holds only the Apache-2.0 text. Hosting platforms such as GitLab
  detect the project license from this file, so no other license text is appended to it.
- **The texts of all licenses used in the repository are in the `LICENSES/` directory.**
  See [The LICENSES directory](#the-licenses-directory).

## SPDX license identifiers

Every file states its license with an SPDX license identifier in its header comment. A file of
the project looks like this:

```c
/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */
```

- **The identifiers come from the SPDX License List**, for example `Apache-2.0`, `BSD-3-Clause`,
  `BSD-2-Clause`, `Unlicense`.
- **A file with code under more than one license names all of them with `AND`**, for example
  `Apache-2.0 AND BSD-3-Clause`. `AND` means that both licenses apply at the same time. `OR`
  would mean a choice between the licenses and is not correct for this case.
- **The operators `AND`, `OR` and `WITH` are written in upper case.**
- **An identifier is a statement about the license, not formatting.**
  It is only changed after checking under which licenses the content of the file is.

Links:

- SPDX License List: https://spdx.org/licenses/
- SPDX License Expressions: https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/

## The LICENSES directory

The directory holds one file per license, named after its SPDX identifier (REUSE layout):

| File | License | Used by |
|---|---|---|
| `LICENSES/Apache-2.0.txt` | Apache License 2.0 | The project |
| `LICENSES/BSD-3-Clause.txt` | BSD 3-Clause | Contiki (Swedish Institute of Computer Science) and er-coap (ETH Zurich) derived files |
| `LICENSES/BSD-2-Clause.txt` | BSD 2-Clause | c-timestamp |
| `LICENSES/Unlicense.txt` | The Unlicense | `port/mdns/mdns.h` |

- **The texts are the ones the repository carried in its files.**
  Word for word they equal the texts of the SPDX License List, apart from the copyright lines and
  the name of the copyright holder in the BSD texts.
- **`LICENSES/BSD-3-Clause.txt` carries both BSD-3-Clause copyright lines.**
  The terms of the Swedish Institute of Computer Science and of ETH Zurich are identical apart
  from the copyright line. Which holder applies to which file is stated by the copyright line in
  the file and by the tables below.
- **The repository is always distributed with this directory.**
  The SPDX identifier in a file refers to the text there.
- **Binary distributions need the notices in their documentation.**
  Clause 2 of the BSD licenses requires the copyright notice, the conditions and the disclaimer in
  the documentation or other materials of a binary distribution, for example device firmware. This
  applies independently of the header format in the source files.

Link: REUSE specification: https://reuse.software/spec/

## File categories

### Own files

Files written for this project.

- Copyright lines and `SPDX-License-Identifier: Apache-2.0`, no license text in the file.

### Own files with third-party origin

Files that originate from third-party code and that the project maintains and changes as its own
code.

- **All copyright lines stay**, including the line of the third party and its "All rights
  reserved.", directly under that line.
- **The identifier names both licenses**, `Apache-2.0 AND BSD-3-Clause`.
- **The license text is not in the file.** It is in `LICENSES/BSD-3-Clause.txt`, which is always
  distributed with the code.
- **Attribution lines stay**, for example "This file is part of the Contiki operating system."
  and author lines.

Example header:

```c
/*
 * Copyright (c) 2004 Swedish Institute of Computer Science.
 * All rights reserved.
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
 *
 * This file is part of the Contiki operating system.
 * Author: Adam Dunkels <adam@sics.se>
 */
```

The files and the holder of their BSD-3-Clause part:

| Files | Origin | Holder of the BSD-3-Clause part |
|---|---|---|
| `messaging/coap/coap.c`, `coap.h`, `conf.h`, `constants.h`, `engine.c`, `engine.h`, `observe.c`, `observe.h`, `transactions.c`, `transactions.h` | er-coap | Institute for Pervasive Computing, ETH Zurich (2013) |
| `util/oc_etimer.c`, `oc_etimer.h`, `oc_list.c`, `oc_list.h`, `oc_mmem.c`, `oc_mmem.h`, `oc_process.c`, `oc_process.h`, `port/oc_clock.h` | Contiki | Swedish Institute of Computer Science (2004, 2005) |

### Pure third-party files

Files taken over from a third party and not maintained as own code.

- **The license text stays in the file, verbatim**, as the third party wrote it.
- **The file carries the correct SPDX identifier in addition.** When both are present, the full
  text takes priority and the identifier is informational (see the FreeBSD policy below).
- **No Apache-2.0 header is added.**

The files:

| Files | Copyright holder | Identifier |
|---|---|---|
| `api/c-timestamp/timestamp.h`, `timestamp_compare.c`, `timestamp_format.c`, `timestamp_parse.c`, `timestamp_tm.c`, `timestamp_valid.c` | Christian Hansen (2014) | `BSD-2-Clause` |
| `util/pt/lc-addrlabels.h`, `lc-switch.h`, `lc.h`, `pt-sem.h`, `pt.h` | Swedish Institute of Computer Science (2004, 2004-2005) | `BSD-3-Clause` |
| `util/oc_timer.c`, `util/oc_timer.h` | Swedish Institute of Computer Science (2004) | `BSD-3-Clause` |
| `port/mdns/mdns.h` (with `LICENSE` and `README.md` next to it) | Mattias Jansson, released into the public domain | `Unlicense` |

## Rules for changes

- **Never remove or change copyright lines.**
  SPDX, "Handling License Info", section "Copyright notices": "you should not remove or modify
  existing copyright notices in files when adding an SPDX ID."
  https://spdx.dev/learn/handling-license-info/
- **`AND <license>` is only correct while code under that license is still in the file.**
  A file that was rewritten completely may no longer carry the third-party license. This is
  checked per file.
- **Automated header normalization must skip pure third-party files.**
  A normalization pass in 2026 put `Apache-2.0` on the protothread headers in `util/pt/`, which
  carry only the BSD-3-Clause notice of the Swedish Institute of Computer Science. The headers are
  restored to their original form since.
- **New third-party code keeps its license text** and gets the correct identifier in addition. A
  license that is not yet in `LICENSES/` is added there.
- **New own files use the short SPDX form** shown at the top, without license text.

## Findings and references

### Against removing license texts from third-party files

- **Apache Software Foundation, "ASF Source Header and Copyright Notice Policy", section
  "Treatment of Third-Party Works":**
  "Do not modify or remove any copyright notices or licenses within third-party works." and "Do
  not add the standard Apache License header to the top of third-party source files."
  https://www.apache.org/legal/src-headers.html
- **FreeBSD Licensing Policy:**
  "When both SPDX-License-Identifier and the full text of the license are present, the full text
  takes priority and the SPDX-License-Identifier is informational only."
  https://docs.freebsd.org/en/articles/license-guide/

### For SPDX identifiers with the license texts in a central directory

- **FreeBSD Licensing Policy:**
  "SPDX-only license marking (without reproducing the full license text) is preferred." and "To
  comply with the REUSE Software standard as much as possible, all license files will be stored in
  the LICENSES/ directory of the repository."
  https://docs.freebsd.org/en/articles/license-guide/
- **Linux kernel licensing rules:**
  "An alternative to boilerplate text is the use of Software Package Data Exchange (SPDX) license
  identifiers in each source file." and "Due to formatting, typos etc. these "boilerplates" are
  hard to validate for tools which are used in the context of license compliance."
  https://docs.kernel.org/process/license-rules.html
- **SPDX, "Using SPDX License List short identifiers in source files":**
  "If using SPDX short identifiers in individual files, it is recommended to reproduce the full
  license in the projects LICENSE file and indicate that SPDX short identifiers are being used to
  refer to it."
  https://spdx.github.io/using/license-id-in-source/
- **REUSE FAQ, "... deal with license texts which include copyright statements, like MIT/BSD?":**
  "The most pragmatic solution is to put the unmodified license text (i.e., the license text
  template without any copyright notices) in your `LICENSES/` folder."
  https://reuse.software/faq/

### A precedent in the Linux kernel

Linux mainline commit b29580d58be6, "net: ntb_netdev: add SPDX tag and remove boilerplate license
text" (2026), replaced the full BSD-3-Clause and GPL-2.0 license text of
`drivers/net/ntb_netdev.c` with `// SPDX-License-Identifier: GPL-2.0-only OR BSD-3-Clause`,
relying on the license texts in the kernel's `LICENSES/` directory. Its commit message: "Add
SPDX-License-Identifier tag to reflect the dual GPL-2.0-only/BSD-3-Clause license, remove the
redundant boilerplate license text and contact information, keeping only the driver description."

- It was acked from the side of a copyright holder of the file (Intel) and applied by the netdev
  maintainer.
- The kernel has a documented tree-wide SPDX policy.

https://github.com/torvalds/linux/commit/b29580d58be6d4d24d66c89d9bea96db342cff00

### Conclusion

- Pure third-party files keep their license text verbatim. This follows the ASF policy for
  third-party works and the FreeBSD rule that the full text takes priority. The correct SPDX
  identifier is added for machine readability.
- Own files with third-party origin carry all copyright lines and an identifier that names every
  license that applies, with the license texts in `LICENSES/`, distributed with the code. This
  follows the practice of FreeBSD, the Linux kernel and REUSE.
