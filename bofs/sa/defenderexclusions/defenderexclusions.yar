rule Armory_BOF_sa_defenderexclusions
{
    meta:
        description = "Compiled Rust BOF: defenderexclusions"
        author = "memN0ps"

    strings:
        $crate = "defenderexclusions" ascii
        $capability = "Configured registry state only; effective protection may differ." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
