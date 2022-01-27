Develop based on [HyperPlatForm](https://github.com/tandasat/HyperPlatform) and Only x64.


## Feature

Support log process' systemcalls and easy ept-hook (NtOpenProcess or NtCreateFile .etc)

Support hook win32kfull.sys funtions.

Add hide window (attack gpKernelHandleTable and hook FindWindow).


## Only effect on win10 1809 17763.437

# Use [tool](https://github.com/helloobaby/pdbtoheader.git) to change include\PDBSDK that effect on your system(this means change all hard signature that depend on specific system)

# Pay attention to header file "settings.h" ,hooked functions are implemented at service_hook.cpp about line 360








