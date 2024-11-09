#pragma once
#include <ntifs.h>
#define ULLONG_MAX    0xffffffffffffffffui64       /* maximum unsigned long long int value */
#define KCRT_POOL_DEFAULT_TAG	'kcrt'

void k_free(void* ptr);
void* k_malloc(size_t size);
void* k_realloc(void* ptr, size_t new_size);
unsigned long long k_strtoull(char const* _String, char** _EndPtr, int _Radix);