rule Armory_BOF_sa_netuserenum
{
    meta:
        description = "Compiled Rust BOF: netuserenum"
        author = "memN0ps"

    strings:
        $crate = "netuserenum" ascii
        $capability = ". Use 1=all, 2=locked, 3=disabled, 4=active." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
