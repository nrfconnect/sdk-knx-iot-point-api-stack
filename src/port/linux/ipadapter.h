/*
 * Copyright (c) 2019 Jozef Kralik All Rights Reserved.
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "ipcontext.h"

int set_nonblock_socket(int sockfd);
ip_context_t *get_ip_context_for_device(void);
