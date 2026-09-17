rule Armory_BOF_sa_get_session_info
{
    meta:
        description = "Compiled Rust BOF: get_session_info"
        author = "memN0ps"

    strings:
        $crate = "get_session_info" ascii
        $capability = "LsaGetLogonSessionData returned null" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
