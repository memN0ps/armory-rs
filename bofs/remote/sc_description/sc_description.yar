rule Armory_BOF_remote_sc_description
{
    meta:
        description = "Compiled Rust BOF: sc_description"
        author = "memN0ps"

    strings:
        $crate = "sc_description" ascii
        $capability = "set_service_description:" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
