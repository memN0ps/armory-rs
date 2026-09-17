rule Armory_BOF_remote_reg_delete
{
    meta:
        description = "Compiled Rust BOF: reg_delete"
        author = "memN0ps"

    strings:
        $crate = "reg_delete" ascii
        $capability = " (use 0=HKCR, 1=HKCU, 2=HKLM, 3=HKU)" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
