rule Armory_BOF_injection_svcctrl
{
    meta:
        description = "Compiled Rust BOF: svcctrl"
        author = "memN0ps"

    strings:
        $crate = "svcctrl" ascii
        $capability = "SUCCESS - svcctrl injection variant, remote thread created." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
