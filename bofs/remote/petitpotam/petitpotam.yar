rule Armory_BOF_remote_petitpotam
{
    meta:
        description = "Compiled Rust BOF: petitpotam"
        author = "memN0ps"

    strings:
        $crate = "petitpotam" ascii
        $capability = "). Confirm listener telemetry before claiming forced authentication." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
