rule Armory_BOF_sa_sc_qfailure
{
    meta:
        description = "Compiled Rust BOF: sc_qfailure"
        author = "memN0ps"

    strings:
        $crate = "sc_qfailure" ascii
        $capability = "SERVICE_NAME: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
