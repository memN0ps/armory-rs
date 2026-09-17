rule Armory_BOF_sa_dir
{
    meta:
        description = "Compiled Rust BOF: dir"
        author = "memN0ps"

    strings:
        $crate = "dir" ascii
        $capability = " Total File Size for " ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
