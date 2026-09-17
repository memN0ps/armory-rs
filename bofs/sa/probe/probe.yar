rule Armory_BOF_sa_probe
{
    meta:
        description = "Compiled Rust BOF: probe"
        author = "memN0ps"

    strings:
        $crate = "probe" ascii
        $capability = "Invalid IP address: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
