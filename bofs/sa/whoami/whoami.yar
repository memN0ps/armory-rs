rule Armory_BOF_sa_whoami
{
    meta:
        description = "Compiled Rust BOF: whoami"
        author = "memN0ps"

    strings:
        $crate = "whoami" ascii
        $capability = "PRIVILEGES INFORMATION" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
