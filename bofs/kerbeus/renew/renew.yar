rule Armory_BOF_kerbeus_renew
{
    meta:
        description = "Compiled Rust BOF: renew"
        author = "memN0ps"

    strings:
        $crate = "renew" ascii
        $capability = "[*] /ptt: use the ptt BOF to import this ticket" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
