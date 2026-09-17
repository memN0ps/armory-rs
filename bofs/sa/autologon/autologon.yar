rule Armory_BOF_sa_autologon
{
    meta:
        description = "Compiled Rust BOF: autologon"
        author = "memN0ps"

    strings:
        $crate = "autologon" ascii
        $capability = "[*] No AutoAdminLogon values were present." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
