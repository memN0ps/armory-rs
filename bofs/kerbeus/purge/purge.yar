rule Armory_BOF_kerbeus_purge
{
    meta:
        description = "Compiled Rust BOF: purge"
        author = "memN0ps"

    strings:
        $crate = "purge" ascii
        $capability = "[+] Successfully purged tickets." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
