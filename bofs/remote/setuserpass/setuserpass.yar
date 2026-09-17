rule Armory_BOF_remote_setuserpass
{
    meta:
        description = "Compiled Rust BOF: setuserpass"
        author = "memN0ps"

    strings:
        $crate = "setuserpass" ascii
        $capability = "SUCCESS: Password changed for user '" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
