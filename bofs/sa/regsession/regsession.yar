rule Armory_BOF_sa_regsession
{
    meta:
        description = "Compiled Rust BOF: regsession"
        author = "memN0ps"

    strings:
        $crate = "regsession" ascii
        $capability = "Enumerating logged-on user SIDs from HKEY_USERS on " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
