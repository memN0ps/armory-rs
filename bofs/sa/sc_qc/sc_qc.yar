rule Armory_BOF_sa_sc_qc
{
    meta:
        description = "Compiled Rust BOF: sc_qc"
        author = "memN0ps"

    strings:
        $crate = "sc_qc" ascii
        $capability = "SERVICE_NAME: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
