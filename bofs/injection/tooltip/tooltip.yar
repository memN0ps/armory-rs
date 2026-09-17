rule Armory_BOF_injection_tooltip
{
    meta:
        description = "Compiled Rust BOF: tooltip"
        author = "memN0ps"

    strings:
        $crate = "tooltip" ascii
        $capability = "SUCCESS - tooltip injection variant, remote thread created." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
