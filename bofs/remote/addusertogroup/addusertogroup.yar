rule Armory_BOF_remote_addusertogroup
{
    meta:
        description = "Compiled Rust BOF: addusertogroup"
        author = "memN0ps"

    strings:
        $crate = "addusertogroup" ascii
        $capability = "' added to group '" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
