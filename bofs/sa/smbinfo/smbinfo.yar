rule Armory_BOF_sa_smbinfo
{
    meta:
        description = "Compiled Rust BOF: smbinfo"
        author = "memN0ps"

    strings:
        $crate = "smbinfo" ascii
        $capability = "Remote workstation information: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
