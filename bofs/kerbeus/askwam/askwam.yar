rule Armory_BOF_kerbeus_askwam
{
    meta:
        description = "Compiled Rust BOF: askwam"
        author = "memN0ps"

    strings:
        $crate = "askwam" ascii
        $capability = "account enumeration cannot be combined with an account selector" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
