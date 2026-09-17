rule Armory_BOF_kerbeus_s4u
{
    meta:
        description = "Compiled Rust BOF: s4u"
        author = "memN0ps"

    strings:
        $crate = "s4u" ascii
        $capability = "[*] Import the ticket with the ptt BOF" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
