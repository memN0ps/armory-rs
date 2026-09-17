rule Armory_BOF_sa_netloggedon
{
    meta:
        description = "Compiled Rust BOF: netloggedon"
        author = "memN0ps"

    strings:
        $crate = "netloggedon" ascii
        $capability = "Logged on users at " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
