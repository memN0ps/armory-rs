rule Armory_BOF_kerbeus_describe
{
    meta:
        description = "Compiled Rust BOF: describe"
        author = "memN0ps"

    strings:
        $crate = "describe" ascii
        $capability = "RenewTill (UTC)          :  " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
