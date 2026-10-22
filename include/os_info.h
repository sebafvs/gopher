//
// Created by seba on 10/17/26.
//

#ifndef GOPHER_OS_INFO_H
#define GOPHER_OS_INFO_H

#include "common.h"
#include "profile.h"

void os_collect_info  (SessionInfo *info);
void session_info_free(SessionInfo *info);
bool os_is_elevated   (void);
char *os_get_version  (void);
char *os_get_ipv4     (void);

#endif
