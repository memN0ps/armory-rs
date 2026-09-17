rule Armory_BOF_injection_kernelcallbacktable
{
    meta:
        description = "Compiled Rust BOF: kernelcallbacktable"
        author = "memN0ps"

    strings:
        $crate = "kernelcallbacktable" ascii
        $capability = "SUCCESS: Shellcode injected via PEB KernelCallbackTable hijacking" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
