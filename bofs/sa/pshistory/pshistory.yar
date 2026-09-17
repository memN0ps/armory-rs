rule Armory_BOF_sa_pshistory
{
    meta:
        description = "Compiled Rust BOF: pshistory"
        author = "memN0ps"

    strings:
        $crate = "pshistory" ascii
        $capability = "No PSReadLine console history was found for the current user." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
