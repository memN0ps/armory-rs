rule Armory_BOF_remote_machineaccount
{
    meta:
        description = "Compiled Rust BOF: machineaccount"
        author = "memN0ps"

    strings:
        $crate = "machineaccount" ascii
        $capability = " created and verified. Run the matching delete action to roll it back." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
