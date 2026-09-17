rule Armory_BOF_remote_sc_stop
{
    meta:
        description = "Compiled Rust BOF: sc_stop"
        author = "memN0ps"

    strings:
        $crate = "sc_stop" ascii
        $capability = "Service is already stopped." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
