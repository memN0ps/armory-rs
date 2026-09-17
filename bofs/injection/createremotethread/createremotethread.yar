rule Armory_BOF_injection_createremotethread
{
    meta:
        description = "Compiled Rust BOF: createremotethread"
        author = "memN0ps"

    strings:
        $crate = "createremotethread" ascii
        $capability = "SUCCESS - remote thread created." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
