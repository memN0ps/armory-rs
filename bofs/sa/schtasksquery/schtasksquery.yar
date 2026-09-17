rule Armory_BOF_sa_schtasksquery
{
    meta:
        description = "Compiled Rust BOF: schtasksquery"
        author = "memN0ps"

    strings:
        $crate = "schtasksquery" ascii
        $capability = "schtasksquery:" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
