rule Armory_BOF_sa_sc_qtriggerinfo
{
    meta:
        description = "Compiled Rust BOF: sc_qtriggerinfo"
        author = "memN0ps"

    strings:
        $crate = "sc_qtriggerinfo" ascii
        $capability = "SERVICE_NAME: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
