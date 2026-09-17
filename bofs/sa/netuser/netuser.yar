rule Armory_BOF_sa_netuser
{
    meta:
        description = "Compiled Rust BOF: netuser"
        author = "memN0ps"

    strings:
        $crate = "netuser" ascii
        $capability = "NetUserGetInfo returned null buffer" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
