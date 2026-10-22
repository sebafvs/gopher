//
// Created by seba on 10/17/26.
//

#include "os_info.h"
#include "crypt.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/types.h>

bool os_is_elevated(void) {
    return getuid() == 0;
}

char *os_get_version(void) {
    FILE *f = fopen("/etc/os-release", "r");
    if (!f) return strdup("Linux");

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "PRETTY_NAME=", 12) == 0) {
            fclose(f);
            char *val = line + 12;
            size_t len = strlen(val);
            while (len > 0 && (val[len - 1] == '\n' || val[len - 1] == '"')) len--;
            if (val[0] == '"') { val++; len--; }
            char *out = malloc(len + 1);
            if (!out) return strdup("Linux");
            memcpy(out, val, len);
            out[len] = '\0';
            return out;
        }
    }
    fclose(f);
    return strdup("Linux");
}

char *os_get_ipv4(void) {
    struct ifaddrs *ifa_list = NULL;
    if (getifaddrs(&ifa_list) != 0) return strdup("0.0.0.0");

    char *result = NULL;
    for (struct ifaddrs *ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;

        struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
        uint32_t addr = ntohl(sa->sin_addr.s_addr);
        if (addr == 0x7F000001) continue;  // skip 127.0.0.1

        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
        result = strdup(buf);
        break;
    }

    freeifaddrs(ifa_list);
    return result ? result : strdup("0.0.0.0");
}

void os_collect_info(SessionInfo *info) {
    memset(info, 0, sizeof(*info));

    char exe[256];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0) {
        exe[n] = '\0';
        char *base = strrchr(exe, '/');
        info->process = strdup(base ? base + 1 : exe);
    } else {
        info->process = strdup("gopher");
    }

    info->pid = (int)getpid();

    struct passwd *pw = getpwuid(getuid());
    info->user = strdup(pw ? pw->pw_name : "unknown");

    char host[256] = {0};
    gethostname(host, sizeof(host) - 1);
    info->host = strdup(host);

    info->ipaddr   = os_get_ipv4();
    info->elevated = os_is_elevated();
    info->acp      = 65001;  // UTF-8, Linux default
    info->oem      = 65001;
    info->os       = strdup("linux");
    info->os_version = os_get_version();

    crypt_random(info->encrypt_key, 16);
}

void session_info_free(SessionInfo *info) {
    free(info->process);
    free(info->user);
    free(info->host);
    free(info->ipaddr);
    free(info->os);
    free(info->os_version);
    memset(info, 0, sizeof(*info));
}
