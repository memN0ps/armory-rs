rule Armory_BOF_remote_slack_cookie
{
    meta:
        description = "Compiled Rust BOF: slack_cookie"
        author = "memN0ps"

    strings:
        $crate = "slack_cookie" ascii
        $capability = " for Slack auth cookies (xoxd- prefix)" ascii

    condition:
        uint16(0) == 0x8664 and all of them
}
