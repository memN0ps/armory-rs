rule Armory_BOF_sa_netuptime
{
    meta:
        description = "Compiled Rust BOF: netuptime"
        author = "memN0ps"

    strings:
        $crate = "netuptime" ascii
        $capability = "Unable to retrieve uptime remotely: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
