rule Armory_BOF_sa_processtokens
{
    meta:
        description = "Compiled Rust BOF: processtokens"
        author = "memN0ps"

    strings:
        $crate = "processtokens" ascii
        $capability = "Process token inventory" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
