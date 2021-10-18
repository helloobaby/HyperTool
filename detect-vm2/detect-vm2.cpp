#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <immintrin.h>
#include <string.h>
#include<intrin.h>


int main(int argc, char** argv) {

#pragma region 测试单条rdtsc花费的tick
	//
	//在本机大约是0x20-0x30左右，vmware上是0x40，说明vmware默认本身是不接管rdtsc的
	//加载了HyperPlatForm接管rdtsc之后，基本在小0x10000
	//
	auto time1 = __rdtsc();
	_asm rdtsc;
	auto time2 = __rdtsc();

	printf("single rdtsc spend %llx tick\n", time2 - time1);
#pragma endregion

#pragma region rdtsc+cpuid+rdtsc
	auto time11 = __rdtsc();
	_asm cpuid;
	auto time22 = __rdtsc();

	printf("rdtsc + cpuid +rdtsc spend %llx tick\n", time22 - time11);
#pragma endregion 



	return 0;
}