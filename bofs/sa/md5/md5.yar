rule Armory_BOF_sa_md5
{
    meta:
        description = "Compiled Rust BOF: md5"
        author = "memN0ps"

    strings:
        $crate = "md5" ascii
        $capability = "Error: Could not initialize HCRYPTPROV context" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
