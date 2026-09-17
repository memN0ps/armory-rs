rule Armory_BOF_sa_certenum
{
    meta:
        description = "Compiled Rust BOF: certenum"
        author = "memN0ps"

    strings:
        $crate = "certenum" ascii
        $capability = "Personal certificate inventory" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
