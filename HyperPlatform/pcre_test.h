#pragma once
#include "regex/pcre_regex.h"
#include "log.h"


void pcre_test(){
	HYPERPLATFORM_LOG_INFO("%d",_ismatch((char*)"C:\\Windows\\explorer.exe", (char*)"((?i)explorer)|system")); // 2
	HYPERPLATFORM_LOG_INFO("%d", _ismatch((char*)"C:\\Windows\\Explorer.exe", (char*)"((?i)explorer)|system")); // 2
	HYPERPLATFORM_LOG_INFO("%d", _ismatch((char*)"C:\\Windows\\Explorer.exe", (char*)"(?i)explorer|system")); // 1
	HYPERPLATFORM_LOG_INFO("%d", _ismatch((char*)"C:\\Windows\\system", (char*)"((?i)explorer)|system"));// 1 
	HYPERPLATFORM_LOG_INFO("%d", _ismatch((char*)"C:\\Windows\\System", (char*)"((?i)explorer)|system")); // -1
	HYPERPLATFORM_LOG_INFO("%d", _ismatch((char*)"D:\\develop-tool\\systeminformer-3.0.6806-bin\\amd64\\SystemInformer.exe", (char*)"((?i)explorer)|system")); // 1
}