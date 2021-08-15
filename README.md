Project repository: https://github.com/rdruzhkov/Hook-Inject

Comment: 
This is solvation for one of my university's tasks. Shortened task statement: 

Write WIN API hooking programm that will allow to:
1. Track calls of specified WIN API functions for specified process.
2. Hide specified file for process.

Syntax:

    Monitor.exe <(-pid <target process pid>) | (-name <target_process_name>)> <(-func <function_name_to_track>) | (-hide <file_to_hide_name>)>

Notes and Restrictions:   
1. (IMPORTANT) Both processes (target and Monitor.exe) should be ran in the same mode (user or administrator).   
2. It is assumed that injection.dll is located in the same place with Monitor.exe.  
3. Tested only x64 build.
4. Works only for kernel32.dll WIN APIs.

Example of using #1:

    1. devenv Hook-Inject.sln /build Release
    2. Enter "App" folder.
    3. Run mspaint.exe
    4. Run cmd inside of "App" folder and run there command "Monitor.exe -name mspaint.exe -func CloseHandle"
    5. Paint in mspaint.exe and see when CloseHandle function was called.

Example of using #2:

    1. devenv Hook-Inject.sln /build Release
    2. Enter "App" folder.
    3. Run cmd and get it's process pid (for example pid = 7777).
    4. Run cmd inside of "App" folder and run there command "Monitor.exe -pid 7777 -hide notepad.exe"
    5. Run command "dir c:\windows\system32\not*.exe" in cmd with pid 7777.
    6. See that dir command couldn't find file notepad.exe.
