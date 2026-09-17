rule Armory_BOF_kerbeus_asktgs
{
    meta:
        description = "Compiled Rust BOF: asktgs"
        author = "memN0ps"

    strings:
        $crate = "asktgs" ascii
        $capability = "[*] /ptt: use the ptt BOF to import this ticket" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
