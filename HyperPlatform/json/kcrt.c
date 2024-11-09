#include "kcrt.h"
typedef struct _MALLOC_HEADER
{
	ULONG32 Tags;
	ULONG32 _Resv0;
	ULONG_PTR Size;
}MALLOC_HEADER, * PMALLOC_HEADER;
C_ASSERT(sizeof(MALLOC_HEADER) % sizeof(void*) == 0);
PMALLOC_HEADER GET_MALLOC_HEADER(PVOID ptr) {
	return (MALLOC_HEADER*)((PUCHAR)ptr - sizeof(MALLOC_HEADER));
}
PVOID GET_MALLOC_ADDRESS(PMALLOC_HEADER header) {
	return (PVOID)((PUCHAR)header + sizeof(MALLOC_HEADER));
}
ULONG_PTR GET_MALLOC_SIZE(PVOID ptr) {
	PMALLOC_HEADER header = GET_MALLOC_HEADER(ptr);

	if (header->Tags != KCRT_POOL_DEFAULT_TAG)
		KeBugCheckEx(BAD_POOL_HEADER, 0, 0, 0, 0);

	return header->Size;
}

#pragma warning(push)
#pragma warning(disable:28251)
int k_isalpha(_In_ int _C)
{
	return ((_C >= 'a' && _C <= 'z') || (_C >= 'A' && _C <= 'Z') ? 1 : 0);
}
unsigned long long k_strtoull(char const* str,char** end,int radix)
{
    const char* s = str;
    unsigned long long acc;
    int c;
    unsigned long long cutoff;
    int neg = 0, cutlim, any;
    do {
        c = *s++;
    } while (isspace(c));
    if (c == '-') {
        neg = 1;
        c = *s++;
    }
    else if (c == '+')
        c = *s++;
    if ((radix == 0 || radix == 16) &&
        c == '0' && (*s == 'x' || *s == 'X')) {
        c = s[1];
        s += 2;
        radix = 16;
    }
    if (radix == 0)
        radix = c == '0' ? 8 : 10;
    cutoff = (unsigned long long)ULLONG_MAX / (unsigned long long)radix;
    cutlim = (unsigned long long)ULLONG_MAX % (unsigned long long)radix;
    for (acc = 0, any = 0;; c = *s++) {
        if (isdigit(c))
            c -= '0';
        else if (k_isalpha(c))
            c -= isupper(c) ? 'A' - 10 : 'a' - 10;
        else
            break;
        if (c >= radix)
            break;
        if (any < 0 || acc > cutoff || (acc == cutoff && c > cutlim))
            any = -1;
        else {
            any = 1;
            acc *= radix;
            acc += c;
        }
    }
    if (any < 0) {
        acc = ULLONG_MAX;
    }
    else if (neg)
        acc = 0 - acc;
    if (end != 0)
        *end = (char*)(any ? s - 1 : str);
    return (acc);
}
void k_free(void* ptr) 
{
	if (ptr) {
		MALLOC_HEADER* mhdr = GET_MALLOC_HEADER(ptr);

		if (mhdr->Tags != KCRT_POOL_DEFAULT_TAG)
			KeBugCheckEx(BAD_POOL_HEADER, 0, 0, 0, 0);

		ExFreePool(mhdr);
	}
}
void* k_malloc(size_t size) 
{
	PMALLOC_HEADER mhdr = NULL;
	const size_t new_size = size + sizeof(MALLOC_HEADER);

	mhdr = (PMALLOC_HEADER)ExAllocatePoolWithTag(NonPagedPool, new_size, KCRT_POOL_DEFAULT_TAG);
	if (mhdr) {
		RtlZeroMemory(mhdr, new_size);

		mhdr->Tags = KCRT_POOL_DEFAULT_TAG;
		mhdr->Size = size;
		return GET_MALLOC_ADDRESS(mhdr);
	}

	return NULL;
}
void* k_realloc(void* ptr, size_t new_size)
{
	if (!ptr) {
		return k_malloc(new_size);
	}
	else if (new_size == 0) {
		k_free(ptr);
		return NULL;
	}
	else {
		size_t old_size = GET_MALLOC_SIZE(ptr);

		if (new_size <= old_size) {
			return ptr;
		}
		else {
			void* new_ptr = k_malloc(new_size);

			if (new_ptr) {
				memcpy(new_ptr, ptr, old_size);
				k_free(ptr);
				return new_ptr;
			}
		}
	}

	return NULL;
}
#pragma warning(pop)