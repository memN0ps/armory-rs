rule Armory_BOF_kerbeus_ptt
{
    meta:
        description = "Compiled Rust BOF: ptt"
        author = "memN0ps"

    strings:
        $crate = "ptt" ascii
        $capability = "[+] Ticket successfully imported." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
