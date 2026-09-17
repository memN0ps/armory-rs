rule Armory_BOF_remote_lapsdump
{
    meta:
        description = "Compiled Rust BOF: lapsdump"
        author = "memN0ps"

    strings:
        $crate = "lapsdump" ascii
        $capability = "[+] LAPS attributes for " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
