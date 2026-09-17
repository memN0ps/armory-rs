rule Armory_BOF_sa_sha1
{
    meta:
        description = "Compiled Rust BOF: sha1"
        author = "memN0ps"

    strings:
        $crate = "sha1" ascii
        $capability = "Error: Could not initialize HCRYPTPROV context" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
