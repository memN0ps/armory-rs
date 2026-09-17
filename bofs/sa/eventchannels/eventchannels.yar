rule Armory_BOF_sa_eventchannels
{
    meta:
        description = "Compiled Rust BOF: eventchannels"
        author = "memN0ps"

    strings:
        $crate = "eventchannels" ascii
        $capability = "Windows Event Log channel inventory" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
