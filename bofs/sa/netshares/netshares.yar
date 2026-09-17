rule Armory_BOF_sa_netshares
{
    meta:
        description = "Compiled Rust BOF: netshares"
        author = "memN0ps"

    strings:
        $crate = "netshares" ascii
        $capability = "Share enumeration (admin) at " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
