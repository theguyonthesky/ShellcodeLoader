rule ShellcodeLoader
{
    meta:
        author = "Elmeddin Azizov"
        description = "YARA Rule to detect specified shellcode loader"
        date = "2023-10-08"
   
    strings:
        $func_CryptAcquireContextW = "CryptAcquireContextW"
        $func_CryptCreateHash = "CryptCreateHash"
        $func_CryptHashData = "CryptHashData"
        $func_CryptDeriveKey = "CryptDeriveKey"
        $func_CryptDecrypt = "CryptDecrypt"
        $func_VirtualAlloc = "VirtualAlloc"
        $func_RtlMoveMemory = "RtlMoveMemory"
        $func_VirtualProtect = "VirtualProtect"
        $func_CreateThread = "CreateThread"
        $func_WaitForSingleObject = "WaitForSingleObject"

    condition:
        6 of ($func*)
}
