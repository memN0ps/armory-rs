rule Armory_BOF_sa_trayscout
{
    meta:
        description = "Compiled Rust BOF: trayscout"
        author = "memN0ps"

    strings:
        $crate = "trayscout" ascii
        $capability = "Taskbar host: <not present in this desktop session>" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
