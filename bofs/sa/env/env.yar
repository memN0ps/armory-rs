rule Armory_BOF_sa_env
{
    meta:
        description = "Compiled Rust BOF: env"
        author = "memN0ps"

    strings:
        $crate = "env" ascii
        $capability = "All environment variables:" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
