rule Armory_BOF_kerbeus_kerberoasting
{
    meta:
        description = "Compiled Rust BOF: kerberoasting"
        author = "memN0ps"

    strings:
        $crate = "kerberoasting" ascii
        $capability = "[*] Requesting service ticket for: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
