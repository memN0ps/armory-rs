rule Armory_BOF_remote_lastpass
{
    meta:
        description = "Compiled Rust BOF: lastpass"
        author = "memN0ps"

    strings:
        $crate = "lastpass" ascii
        $capability = "lastpass: Scanning process " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
