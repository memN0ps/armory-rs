rule Armory_BOF_remote_global_unprotect
{
    meta:
        description = "Compiled Rust BOF: global_unprotect"
        author = "memN0ps"

    strings:
        $crate = "global_unprotect" ascii
        $capability = "global_unprotect: Reading GlobalProtect VPN config files" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
