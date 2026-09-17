rule Armory_BOF_remote_chromeKey
{
    meta:
        description = "Compiled Rust BOF: chromeKey"
        author = "memN0ps"

    strings:
        $crate = "chromeKey" ascii
        $capability = "chromeKey: Decrypting Chrome encryption key via DPAPI" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
