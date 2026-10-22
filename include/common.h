//
// Created by seba on 10/17/26.
//

#ifndef GOPHER_COMMON_H
#define GOPHER_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef DEBUG
#define DBG(fmt, ...) fprintf(stderr, "[gopher] " fmt, ##__VA_ARGS__)
#else
#define DBG(fmt, ...) ((void)0)
#endif

#endif //GOPHER_COMMON_H