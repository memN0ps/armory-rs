rule Armory_BOF_sa_netstat
{
    meta:
        description = "Compiled Rust BOF: netstat"
        author = "memN0ps"

    strings:
        $crate = "netstat" ascii
        $capability = "Active Connections" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
