rule Armory_BOF_remote_slackKey
{
    meta:
        description = "Compiled Rust BOF: slackKey"
        author = "memN0ps"

    strings:
        $crate = "slackKey" ascii
        $capability = "Slack storage directory not found - Slack may not be installed." ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
