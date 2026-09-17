rule Armory_BOF_remote_sc_create
{
    meta:
        description = "Compiled Rust BOF: sc_create"
        author = "memN0ps"

    strings:
        $crate = "sc_create" ascii
        $capability = "create_service:" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
