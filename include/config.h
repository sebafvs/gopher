//
// Created by seba on 10/17/26.
//

#ifndef GOPHER_CONFIG_H
#define GOPHER_CONFIG_H

#include <stdint.h>
#include <stddef.h>

static const uint8_t enc_profiles[][GENERATED_PROFILE_SIZE] = {
        // GENERATED_PROFILES_HERE
};

static const size_t enc_profiles_count = sizeof(enc_profiles) / sizeof(enc_profiles[0]);

#endif //GOPHER_CONFIG_H
