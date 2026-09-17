rule Armory_BOF_sa_ideextensions
{
    meta:
        description = "Compiled Rust BOF: ideextensions"
        author = "memN0ps"

    strings:
        $crate = "ideextensions" ascii
        $capability = " | extension manifests: " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
