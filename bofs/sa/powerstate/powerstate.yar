rule Armory_BOF_sa_powerstate
{
    meta:
        description = "Compiled Rust BOF: powerstate"
        author = "memN0ps"

    strings:
        $crate = "powerstate" ascii
        $capability = "Power and chassis state" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
