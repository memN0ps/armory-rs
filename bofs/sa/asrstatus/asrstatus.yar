rule Armory_BOF_sa_asrstatus
{
    meta:
        description = "Compiled Rust BOF: asrstatus"
        author = "memN0ps"

    strings:
        $crate = "asrstatus" ascii
        $capability = "Attack Surface Reduction configuration" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
