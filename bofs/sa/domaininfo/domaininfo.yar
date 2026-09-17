rule Armory_BOF_sa_domaininfo
{
    meta:
        description = "Compiled Rust BOF: domaininfo"
        author = "memN0ps"

    strings:
        $crate = "domaininfo" ascii
        $capability = "Controller address: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
