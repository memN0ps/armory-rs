rule Armory_BOF_remote_reg_set
{
    meta:
        description = "Compiled Rust BOF: reg_set"
        author = "memN0ps"

    strings:
        $crate = "reg_set" ascii
        $capability = " (use REG_SZ, REG_DWORD, REG_EXPAND_SZ, REG_BINARY, REG_QWORD)" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
