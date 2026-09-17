rule Armory_BOF_remote_eventlog
{
    meta:
        description = "Compiled Rust BOF: eventlog"
        author = "memN0ps"

    strings:
        $crate = "eventlog" ascii
        $capability = "Removed owned event-log registration | log=" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
