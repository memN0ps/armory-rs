rule Armory_BOF_sa_credentialfiles
{
    meta:
        description = "Compiled Rust BOF: credentialfiles"
        author = "memN0ps"

    strings:
        $crate = "credentialfiles" ascii
        $capability = "Presence and size only; file contents are not read." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
