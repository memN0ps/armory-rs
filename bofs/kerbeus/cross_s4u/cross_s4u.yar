rule Armory_BOF_kerbeus_cross_s4u
{
    meta:
        description = "Compiled Rust BOF: cross_s4u"
        author = "memN0ps"

    strings:
        $crate = "cross_s4u" ascii
        $capability = "[*] Requesting foreign S4U2Proxy service ticket" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
