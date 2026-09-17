rule Armory_BOF_remote_sc_start
{
    meta:
        description = "Compiled Rust BOF: sc_start"
        author = "memN0ps"

    strings:
        $crate = "sc_start" ascii
        $capability = "servicename: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
