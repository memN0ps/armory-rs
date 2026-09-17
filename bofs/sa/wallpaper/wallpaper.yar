rule Armory_BOF_sa_wallpaper
{
    meta:
        description = "Compiled Rust BOF: wallpaper"
        author = "memN0ps"

    strings:
        $crate = "wallpaper" ascii
        $capability = "] monitor path unavailable: 0x" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
