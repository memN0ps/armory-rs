rule Armory_BOF_kerbeus_asktgt
{
    meta:
        description = "Compiled Rust BOF: asktgt"
        author = "memN0ps"

    strings:
        $crate = "asktgt" ascii
        $capability = "KDC_ERR_C_PRINCIPAL_UNKNOWN - client not found" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
