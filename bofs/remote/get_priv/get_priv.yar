rule Armory_BOF_remote_get_priv
{
    meta:
        description = "Compiled Rust BOF: get_priv"
        author = "memN0ps"

    strings:
        $crate = "get_priv" ascii
        $capability = "SUCCESS: Activated priv " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
