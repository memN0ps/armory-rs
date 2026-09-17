rule Armory_BOF_sa_ldapsecuritycheck
{
    meta:
        description = "Compiled Rust BOF: ldapsecuritycheck"
        author = "memN0ps"

    strings:
        $crate = "ldapsecuritycheck" ascii
        $capability = "[+] LDAPS connection succeeded - SSL/TLS is available." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
