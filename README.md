## Armory

Rust Beacon Object Files (BOFs) for adversary simulation, threat emulation, security research, and detection engineering. All 115 TrustedSec BOFs ported from C to Rust using the [rustbof](https://github.com/joaoviictorti/rustbof) framework.

## Credits

- [MITRE ATT&CK](https://attack.mitre.org/) - Adversarial tactics, techniques, and common knowledge framework
- [rustbof](https://github.com/joaoviictorti/rustbof) by [Joao Victor](https://github.com/joaoviictorti) - Rust BOF framework
- [CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF) by [TrustedSec](https://github.com/trustedsec) - Original C BOFs (Situational Awareness)
- [CS-Remote-OPs-BOF](https://github.com/trustedsec/CS-Remote-OPs-BOF) by [TrustedSec](https://github.com/trustedsec) - Original C BOFs (Remote Operations and Injection)

## Situational Awareness

| BOF | Description | MITRE ATT&CK |
|-----|-------------|---------------|
| `env` | List environment variables | T1082 |
| `uptime` | System uptime, local time, boot time | T1082 |
| `whoami` | Current user, groups, privileges | T1033, T1069 |
| `ipconfig` | Network adapter configuration | T1016 |
| `locale` | System locale, language, country | T1082 |
| `resources` | Memory and disk usage | T1082 |
| `arp` | ARP cache table | T1016 |
| `routeprint` | IPv4 routing table | T1016 |
| `netstat` | TCP/UDP connections with PIDs | T1049 |
| `windowlist` | Desktop window titles | T1010 |
| `dir` | Directory listing | T1083 |
| `listdns` | DNS resolver cache | T1018 |
| `useridletime` | User idle time | T1082 |
| `md5` | MD5 hash of a file | T1083 |
| `sha1` | SHA1 hash of a file | T1083 |
| `sha256` | SHA-256 hash of a file | T1083 |
| `enumlocalsessions` | User sessions | T1033 |
| `nettime` | Remote computer time | T1124 |
| `netuptime` | Remote boot time | T1082 |
| `nslookup` | DNS query | T1018 |
| `probe` | TCP port scanner | T1046 |
| `get_session_info` | Logon session data | T1033 |
| `findLoadedModule` | Find processes with a DLL | T1057 |
| `listmods` | List process modules | T1057 |
| `netloggedon` | Logged-on users | T1033 |
| `netshares` | Network shares | T1135 |
| `netlocalgroup` | Local groups and members | T1069.001 |
| `sc_query` | Service status/enumeration | T1007 |
| `sc_qc` | Service configuration | T1007 |
| `sc_qdescription` | Service description | T1007 |
| `sc_qfailure` | Service failure actions | T1007 |
| `sc_qtriggerinfo` | Service triggers | T1007 |
| `cacls` | File/directory ACL permissions | T1222 |
| `driversigs` | EDR/AV driver signatures | T1518.001 |
| `reg_query` | Registry keys and values | T1012 |
| `enum_filter_driver` | Minifilter drivers | T1518.001 |
| `netuserenum` | Domain/local user accounts | T1087 |
| `netgroup` | Domain groups and members | T1069.002 |
| `get_password_policy` | Password and lockout policies | T1201 |
| `netview` | Network computers | T1018 |
| `get_netsession` | Network sessions | T1049 |
| `netuser` | Detailed user info | T1087.002 |
| `netuse` | Map/disconnect network drives | T1021.002 |
| `regsession` | Logged-on user SIDs from HKU | T1033 |
| `notepad` | Read Notepad window text | T1010 |
| `get_dpapi_system` | DPAPI system keys | T1003.004 |
| `ldapsearch` | LDAP search | T1087.002 |
| `ldapsecuritycheck` | LDAP signing check | T1557.001 |
| `nonpagedldapsearch` | Non-paged LDAP search | T1087.002 |
| `adcs_enum` | ADCS CA enumeration | T1649 |
| `adcs_enum_com` | ADCS enumeration via COM | T1649 |
| `adcs_enum_com2` | ADCS template enumeration | T1649 |
| `adv_audit_policies` | Audit policy settings | T1562.002 |
| `aadjoininfo` | Azure AD join info | T1087.004 |
| `list_firewall_rules` | Firewall rules | T1518 |
| `vssenum` | Volume shadow copies | T1003.003 |
| `wmi_query` | WMI query | T1047 |
| `tasklist` | Process list | T1057 |
| `schtasksenum` | Scheduled tasks | T1053.005 |
| `schtasksquery` | Scheduled task details | T1053.005 |
| `netloggedon2` | Logged-on users (JSON) | T1033 |
| `netlocalgroup2` | Local groups (JSON) | T1069.001 |
| `get_netsession2` | Network sessions (JSON) | T1049 |

## Remote Operations

| BOF | Description | MITRE ATT&CK |
|-----|-------------|---------------|
| `get_priv` | Enable token privilege | T1134.002 |
| `sc_start` | Start a service | T1569.002 |
| `sc_stop` | Stop a service | T1489 |
| `sc_create` | Create a service | T1543.003 |
| `sc_delete` | Delete a service | T1489 |
| `sc_config` | Modify service config | T1543.003 |
| `sc_description` | Set service description | T1543.003 |
| `sc_failure` | Set service failure actions | T1543.003 |
| `suspendresume` | Suspend/resume a process | T1106 |
| `adduser` | Create local user | T1136.001 |
| `addusertogroup` | Add user to group | T1098 |
| `setuserpass` | Change user password | T1098 |
| `disableuser` | Disable user account | T1531 |
| `enableuser` | Enable user account | T1098 |
| `unexpireuser` | Set password no-expire | T1098 |
| `reg_set` | Set registry value | T1112 |
| `reg_delete` | Delete registry key/value | T1112 |
| `reg_save` | Save registry hive | T1003.002 |
| `shutdown` | Shutdown/reboot computer | T1529 |
| `procdump` | Dump process memory | T1003.001 |
| `ProcessListHandles` | List process handles | T1057 |
| `ProcessDestroy` | Close remote handles | T1489 |
| `chromeKey` | Decrypt Chrome key (DPAPI) | T1555.003 |
| `shspawnas` | Spawn as another user | T1134.002 |
| `ask_mfa` | Fake MFA prompt | T1056.002 |
| `office_tokens` | Scan for JWT tokens | T1528 |
| `slack_cookie` | Extract Slack cookie | T1539 |
| `lastpass` | Scan for LastPass data | T1555.005 |
| `slackKey` | Extract Slack API tokens | T1528 |
| `global_unprotect` | Decrypt GlobalProtect config | T1555 |
| `get_azure_token` | Azure OAuth token cache | T1528 |
| `make_token_cert` | Import PFX certificate | T1649 |
| `adcs_request` | ADCS certificate request | T1649 |
| `adcs_request_on_behalf` | ADCS enrollment agent | T1649 |
| `schtaskscreate` | Create scheduled task | T1053.005 |
| `schtasksdelete` | Delete scheduled task | T1053.005 |
| `schtasksrun` | Run scheduled task | T1053.005 |
| `schtasksstop` | Stop scheduled task | T1053.005 |
| `ghost_task` | Hidden scheduled task | T1053.005 |
| `netuse` | Map network drives | T1021.002 |

## Injection

| BOF | Description | MITRE ATT&CK |
|-----|-------------|---------------|
| `createremotethread` | CreateRemoteThread | T1055.001 |
| `ntcreatethread` | NtCreateThreadEx | T1055 |
| `ntqueueapcthread` | APC queue injection | T1055.004 |
| `setthreadcontext` | Thread context hijacking | T1055.003 |
| `clipboard` | Clipboard injection | T1055 |
| `svcctrl` | Service control injection | T1055 |
| `tooltip` | Tooltip injection | T1055 |
| `uxsubclassinfo` | UxSubclassInfo injection | T1055 |
| `conhost` | Console host injection | T1055 |
| `dde` | DDE injection | T1055 |
| `kernelcallbacktable` | KernelCallbackTable hijack | T1055.012 |

## Building

Requires Rust nightly, [boflink](https://github.com/MEhrn00/boflink), [cargo-make](https://github.com/sagiegurari/cargo-make), and MinGW-w64.

```bash
cd bofs/sa/whoami
cargo make
# Output: out/whoami.x64.o
```

Use [COFFLoader](https://github.com/trustedsec/COFFLoader) or any compatible loader to test.

## License and Disclaimer

**License**: MIT. See [LICENSE](./LICENSE)

**Disclaimer**: This project is provided for authorized security testing, educational purposes, and legitimate security research only.

**Permitted use includes:**

- Authorized penetration testing and red team engagements
- Purple teaming, adversary simulation, and threat emulation
- Detection engineering, threat hunting, and security operations
- Blue team and SOC activities including malware reverse engineering
- CTF competitions and security research
- Educational and training purposes

**Prohibited use includes:**

- Unauthorized access to systems or networks
- Any activity that violates applicable laws or regulations
- Use against systems without explicit written authorization

**Liability**: The author assumes no responsibility for misuse, damages, or legal consequences arising from the use of this software. Users are solely responsible for ensuring compliance with all applicable laws, regulations, and organizational policies. By using this software, you agree that you have proper authorization for any systems you interact with.

## Author

[memN0ps](https://github.com/memN0ps)
