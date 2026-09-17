rule Armory_BOF_sa_schtasksenum
{
    meta:
        description = "Compiled Rust BOF: schtasksenum"
        author = "memN0ps"

    strings:
        $crate = "schtasksenum" ascii
        $capability = "schtasksenum:" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
