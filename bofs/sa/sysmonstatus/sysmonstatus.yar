rule Armory_BOF_sa_sysmonstatus
{
    meta:
        description = "Compiled Rust BOF: sysmonstatus"
        author = "memN0ps"

    strings:
        $crate = "sysmonstatus" ascii
        $capability = "Operational event channel: state not specified" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
