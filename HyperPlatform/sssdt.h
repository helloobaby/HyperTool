#pragma once

#include "include/stdafx.h"
#include <intrin.h>

// Shadow SSDT µÿ÷∑
inline ULONG_PTR SSSDTAddress;

namespace sssdt {
	BOOLEAN
		GetKeServiceDescriptorTableShadow(OUT PULONG_PTR SSSDTAddress);
}