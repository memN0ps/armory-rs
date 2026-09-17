rule Armory_BOF_sa_wefstatus
{
    meta:
        description = "Compiled Rust BOF: wefstatus"
        author = "memN0ps"

    strings:
        $crate = "wefstatus" ascii
        $capability = "Subscriptions: <unavailable while the collector service is stopped>" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
