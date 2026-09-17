rule Armory_BOF_remote_sc_delete
{
    meta:
        description = "Compiled Rust BOF: sc_delete"
        author = "memN0ps"

    strings:
        $crate = "sc_delete" ascii
        $capability = "delete_service:" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
