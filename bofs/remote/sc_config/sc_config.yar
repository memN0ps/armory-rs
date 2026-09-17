rule Armory_BOF_remote_sc_config
{
    meta:
        description = "Compiled Rust BOF: sc_config"
        author = "memN0ps"

    strings:
        $crate = "sc_config" ascii
        $capability = "errorcontrol: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
