rule Armory_BOF_sa_get_dpapi_system
{
    meta:
        description = "Compiled Rust BOF: get_dpapi_system"
        author = "memN0ps"

    strings:
        $crate = "get_dpapi_system" ascii
        $capability = "get_dpapi_system: Retrieving DPAPI system keys from LSA secrets" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
