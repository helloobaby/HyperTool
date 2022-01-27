Develop based on [HyperPlatForm](https://github.com/tandasat/HyperPlatform) and Only x64.


## Feature

Support log process' systemcalls and easy ept-hook (NtOpenProcess or NtCreateFile .etc)

Support hook win32kfull.sys funtions.

Add hide window (attack gpKernelHandleTable and hook FindWindow).

# Pay attention:

header file "settings.h" ,hooked functions are implemented at service_hook.cpp about line 360

PDBSDK.h







