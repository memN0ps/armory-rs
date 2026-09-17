rule Armory_BOF_sa_reg_query
{
    meta:
        description = "Compiled Rust BOF: reg_query"
        author = "memN0ps"

    strings:
        $crate = "reg_query" ascii
        $capability = " (use 0=HKCR, 1=HKCU, 2=HKLM, 3=HKU)" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
