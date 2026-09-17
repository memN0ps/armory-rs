rule Armory_BOF_sa_mdmstatus
{
    meta:
        description = "Compiled Rust BOF: mdmstatus"
        author = "memN0ps"

    strings:
        $crate = "mdmstatus" ascii
        $capability = "No MDM enrollment registry exists." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
