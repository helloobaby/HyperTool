#include "anti_scrshoot.h"
#include "include/stdafx.h"
#include "service_hook.h"
#include "systemcall.h"
#include "util.h"
#include <windef.h>
#include "regex/pcre_regex.h"
#include "config.h"

extern "C"
{
	UCHAR* PsGetProcessImageFileName(PEPROCESS Process);
}

extern tagGlobalConfig GlobalConfig;

namespace anti {
	BOOL DetourNtGdiBitBlt(IN HDC hdcDes
		, IN int xDes
		, IN int yDes
		, IN int cxDes
		, IN int cyDes
		, IN HDC hdcSrc
		, IN int xSrc
		, IN int ySrc
		, IN int cxSrc
		, IN int cySrc
		, IN DWORD dwRop
		, IN DWORD dwBackColor
		, IN ULONG fl);
	using NtGdiBitBltType = decltype(&DetourNtGdiBitBlt);
	NtGdiBitBltType OriNtGdiBitBlt;

	BOOL DetourNtGdiBitBlt(IN HDC hdcDes
		, IN int xDes
		, IN int yDes
		, IN int cxDes
		, IN int cyDes
		, IN HDC hdcSrc
		, IN int xSrc
		, IN int ySrc
		, IN int cxSrc
		, IN int cySrc
		, IN DWORD dwRop
		, IN DWORD dwBackColor
		, IN ULONG fl) {
		ENTER_HOOK("NtGdiBitBlt");
		//HYPERPLATFORM_LOG_DEBUG("xDes %d , YDes %d , cxDes %d , cyDes %d , xSrc %d , ySrc %d , cxSrc %d , cySrc %d", xDes, yDes, cxDes, cyDes, xSrc, ySrc, cxSrc, cySrc);

		struct ScreenPixel {
			~ScreenPixel(){}
			int x;
			int y;
		};
		// 常用显示屏分辨率及缩放
		std::vector<ScreenPixel> Full;
		Full.push_back(ScreenPixel(1536, 864)); // DPI = 125%
		Full.push_back(ScreenPixel(1920, 1080));
		Full.push_back(ScreenPixel(2048, 1152)); // DPI = 125%
		Full.push_back(ScreenPixel(2560, 1440));

		if (GlobalConfig.capture.size()) {
			if (_ismatch((char*)PsGetProcessImageFileName(IoGetCurrentProcess()), (char*)GlobalConfig.capture.c_str()) > 0) {
				HYPERPLATFORM_LOG_DEBUG("Capture filter %s", PsGetProcessImageFileName(IoGetCurrentProcess()));
				return OriNtGdiBitBlt(hdcDes, xDes, yDes, cxDes, cyDes, hdcSrc, xSrc, ySrc, cxSrc, cySrc, dwRop, dwBackColor, fl);
			}
		}

		for (auto scr : Full) {
			if (cxDes == scr.x && cyDes == scr.y) {
				HYPERPLATFORM_LOG_INFO("Intercept ScreenShoot");
				// TODO : 自定义返回截图图片
				//	      主要问题在于内核没有类似LoadImageA函数方便的从一个图片构造成HBITMAP
				return false;
			}
		}

		return OriNtGdiBitBlt(hdcDes, xDes, yDes, cxDes, cyDes, hdcSrc, xSrc, ySrc, cxSrc, cySrc, dwRop, dwBackColor, fl);
	}



	bool AntiCapturesInit() {
		NTSTATUS Status;
		// attach到csrss
		PEPROCESS Csrss;
		KAPC_STATE pRkapcState = { 0x00 };
		PVOID NtGdiBitBlt = NULL;

		Status = PsLookupProcessByProcessId(g_CsrssPid, &Csrss);
		if (NT_SUCCESS(Status)) {
			auto _ = make_scope_exit([&]() {
				//KeUnstackDetachProcess(&pRkapcState);
				ObDereferenceObject(Csrss);
				});
			//KeStackAttachProcess(Csrss, &pRkapcState);
			// Parse the PE header and locate the export directory
			PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Win32kfullBase;

			Status = PsLookupProcessByProcessId(g_CsrssPid, &Csrss);
			if (NT_SUCCESS(Status)) {
				if (NT_SUCCESS(MmAttachSession(Csrss, &pRkapcState))) {
				}
				else {
					HYPERPLATFORM_LOG_INFO("Attach Session fail");
					ObDereferenceObject(Csrss);
					return false;
				}
			}
			else {
				HYPERPLATFORM_LOG_INFO("PsLookupProcessByProcessId Csrss fail");
				return false;
			}

			PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)Win32kfullBase + dosHeader->e_lfanew);
			PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)Win32kfullBase +
				ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

			// Get the export table information
			PULONG functions = (PULONG)((PUCHAR)Win32kfullBase + exportDirectory->AddressOfFunctions);
			PUSHORT ordinals = (PUSHORT)((PUCHAR)Win32kfullBase + exportDirectory->AddressOfNameOrdinals);
			PULONG names = (PULONG)((PUCHAR)Win32kfullBase + exportDirectory->AddressOfNames);

			
			// Find the NtGdiFlush function
			for (ULONG i = 0; i < exportDirectory->NumberOfNames; i++)
			{
				PCHAR functionName = (PCHAR)((PUCHAR)Win32kfullBase + names[i]);
				if (strcmp(functionName, "NtGdiBitBlt") == 0)
				{
					USHORT ordinal = ordinals[i];
					NtGdiBitBlt = (PVOID)((PUCHAR)Win32kfullBase + functions[ordinal]);
					break;
				}
			}
			
			HYPERPLATFORM_LOG_INFO("NtGdiBitBlt Address %p", NtGdiBitBlt);
			MmDetachSession(Csrss, &pRkapcState);
			AddServiceHook(NtGdiBitBlt, DetourNtGdiBitBlt, (PVOID*)&OriNtGdiBitBlt, "NtGdiBitBlt");
		}
		else {
			HYPERPLATFORM_LOG_ERROR("Get Csrss EPROCESS Fail");
			KeUnstackDetachProcess(&pRkapcState);
			return false;
		}

		
		return true;
	}
}