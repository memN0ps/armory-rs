rule Armory_BOF_sa_netuse
{
    meta:
        description = "Compiled Rust BOF: netuse"
        author = "memN0ps"

    strings:
        $crate = "netuse" ascii
        $capability = "SUCCESS: Disconnected from " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
