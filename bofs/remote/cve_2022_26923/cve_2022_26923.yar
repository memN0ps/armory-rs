rule Armory_BOF_remote_cve_2022_26923
{
    meta:
        description = "Compiled Rust BOF: cve_2022_26923"
        author = "memN0ps"

    strings:
        $crate = "cve_2022_26923" ascii
        $capability = "Machine name must be 1-15 letters, digits, hyphens, or underscores without a trailing $." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
