rule Armory_BOF_injection_ntcreatethread
{
    meta:
        description = "Compiled Rust BOF: ntcreatethread"
        author = "memN0ps"

    strings:
        $crate = "ntcreatethread" ascii
        $capability = "SUCCESS - remote thread created via NtCreateThreadEx." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
