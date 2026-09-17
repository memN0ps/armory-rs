rule Armory_BOF_sa_uptime
{
    meta:
        description = "Compiled Rust BOF: uptime"
        author = "memN0ps"

    strings:
        $crate = "uptime" ascii
        $capability = "Local time: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
