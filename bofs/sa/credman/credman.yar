rule Armory_BOF_sa_credman
{
    meta:
        description = "Compiled Rust BOF: credman"
        author = "memN0ps"

    strings:
        $crate = "credman" ascii
        $capability = "[*] Credential Manager returned no credentials." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
