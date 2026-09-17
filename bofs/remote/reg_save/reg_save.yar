rule Armory_BOF_remote_reg_save
{
    meta:
        description = "Compiled Rust BOF: reg_save"
        author = "memN0ps"

    strings:
        $crate = "reg_save" ascii
        $capability = " (use HKLM, HKCU, HKCR, HKU, SAM, SYSTEM, SECURITY)" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
