rule Armory_BOF_kerbeus_asreproasting
{
    meta:
        description = "Compiled Rust BOF: asreproasting"
        author = "memN0ps"

    strings:
        $crate = "asreproasting" ascii
        $capability = "[*] Building AS-REQ (w/o preauth) for: '" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
