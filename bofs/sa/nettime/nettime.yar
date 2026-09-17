rule Armory_BOF_sa_nettime
{
    meta:
        description = "Compiled Rust BOF: nettime"
        author = "memN0ps"

    strings:
        $crate = "nettime" ascii
        $capability = "Unable to retrieve time remotely: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
