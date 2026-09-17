rule Armory_BOF_sa_get_password_policy
{
    meta:
        description = "Compiled Rust BOF: get_password_policy"
        author = "memN0ps"

    strings:
        $crate = "get_password_policy" ascii
        $capability = "Maximum password age:     Never expires" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
