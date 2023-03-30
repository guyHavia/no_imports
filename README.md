A Cpp code that generates executable without the Import Address Table in order to hide from static analysis tools such as pestudio, cff explorer...
The code doesnt encrypt the strings so it not totally bullet proof

How to Compile the code in visual studio:
1. compile the code as x86.
2. Linker > Input > Ignore All Default Libraries > Yes (/NODEFAULTLIB)
3. Linker > Advanced > Entry Point > main
4. C/C++ > Code Generation > Security Check > Disable
5. C/C++ > All Options > Basic Runtime Checks option > Default


this code hide himself from static analysis.
it performs the following tasks:
1. query the PEB and find the address space of kernel32.dll
2. Finding the addresses of "GetProcAddress" and "LoadLibraryA" functions inside the kernel32.dll
3. using the addresses to load user32.dll.
run the function "MessageBoxA".
