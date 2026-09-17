rule Armory_BOF_sa_driversigs
{
    meta:
        description = "Compiled Rust BOF: driversigs"
        author = "memN0ps"

    strings:
        $crate = "driversigs" ascii
        $capability = "No known EDR/AV driver signatures detected." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
