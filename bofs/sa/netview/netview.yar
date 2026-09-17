rule Armory_BOF_sa_netview
{
    meta:
        description = "Compiled Rust BOF: netview"
        author = "memN0ps"

    strings:
        $crate = "netview" ascii
        $capability = "Computers on " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
