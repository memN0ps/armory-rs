rule Armory_BOF_sa_aadjoininfo
{
    meta:
        description = "Compiled Rust BOF: aadjoininfo"
        author = "memN0ps"

    strings:
        $crate = "aadjoininfo" ascii
        $capability = "No Azure AD join information available." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
