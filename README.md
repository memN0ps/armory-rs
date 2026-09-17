# Armory

Armory is a collection of Rust Beacon Object Files (BOFs) for Cobalt Strike. It covers situational awareness, local and remote operations, Active Directory and Microsoft Entra ID (Azure AD), Kerberos and LDAP tradecraft, process injection, and post-exploitation. It also includes a Bring Your Own Vulnerable Driver (BYOVD) BOF for removing kernel callbacks, disabling ETW Threat Intelligence, bypassing PPL, enabling WDigest credential caching, swapping process tokens, running a DSE disable-and-restore cycle, and dumping credentials that remain in VTL0 LSASS without `OpenProcess`, even when Credential Guard is enabled. Secrets isolated in VTL1 remain protected.

## Repository layout

- [Situational awareness BOFs](./bofs/sa/)
- [Remote operation BOFs](./bofs/remote/)
- [Process injection BOFs](./bofs/injection/)
- [Kerberos BOFs](./bofs/kerbeus/)
- [Kernel BOF](./bofs/kernel/)
- [Repository build helper](./xtask/) for building and checking the complete catalog

## Complete BOF Index

This is the complete source index. Each link contains the TTP, argument order, build command, example command, redacted output shape, and YARA rule.

<!-- BOF_INDEX_START -->

### Situational Awareness

| BOF | What it does |
|---|---|
| [`aadjoininfo`](./bofs/sa/aadjoininfo/) | Retrieves Azure AD / Entra ID join information for the local device using NetGetAadJoinInformation. Dynamically loads the function from netapi32.dll via LoadLibraryA/GetProcAddress to avoid linker issues with mingw. |
| [`adcs_enum`](./bofs/sa/adcs_enum/) | Enumerates Active Directory Certificate Services (AD CS) Certificate Authorities and certificate templates by dynamically loading certcli.dll and calling the CA enumeration APIs (CAEnumFirstCA, CAEnumCertTypesForCA, etc.). |
| [`adcs_enum_com`](./bofs/sa/adcs_enum_com/) | Enumerates Active Directory Certificate Services (AD CS) configuration using the ICertConfig2 COM interface to discover certificate authorities. |
| [`adcs_enum_com2`](./bofs/sa/adcs_enum_com2/) | Enumerates Active Directory Certificate Services (AD CS) CA information and templates by invoking `certutil -TCAInfo` via `CreateProcessA` and capturing the output through an anonymous pipe. |
| [`adv_audit_policies`](./bofs/sa/adv_audit_policies/) | Queries advanced audit policy settings using AuditQuerySystemPolicy. Enumerates well-known audit subcategories and reports whether success and/or failure auditing is enabled for each. |
| [`aisurface`](./bofs/sa/aisurface/) | Reports the presence of common local AI applications, coding-agent profiles, editor storage, and MCP configuration files. It does not read configuration contents, tokens, session data, or prompts. |
| [`amsietwdetect`](./bofs/sa/amsietwdetect/) | Reports whether AMSI is loaded in the current process and whether selected AMSI and ETW exports are present. It does not inspect code bytes or patch either interface. |
| [`appcount`](./bofs/sa/appcount/) | Counts unique uninstall entries across the current-user and both local-machine registry views without printing application names. |
| [`applocker`](./bofs/sa/applocker/) | Reports Application Identity service state and the configured enforcement mode and rule count for each AppLocker collection. |
| [`arp`](./bofs/sa/arp/) | Lists the local IPv4 ARP cache with interface indexes, MAC addresses, and entry types. |
| [`asrstatus`](./bofs/sa/asrstatus/) | Enumerates locally configured and policy-backed Attack Surface Reduction rules and exclusions without changing Microsoft Defender settings. |
| [`autologon`](./bofs/sa/autologon/) | Reads the Windows Winlogon AutoAdminLogon configuration and reports any configured account and plaintext password values. It does not change the registry. |
| [`bitlocker`](./bofs/sa/bitlocker/) | Reads the local BitLocker volume snapshot exposed by the Microsoft Volume Encryption WMI provider. It does not change encryption or key protectors. |
| [`cacls`](./bofs/sa/cacls/) | Displays file or directory DACL permissions by resolving each ACE to an account name and printing the associated access rights. |
| [`certenum`](./bofs/sa/certenum/) | Enumerates Current User and Local Machine personal certificate stores, including subject, issuer, expiry, enhanced-key usages, SHA-1 thumbprint, and private-key presence. |
| [`clipboardgrab`](./bofs/sa/clipboardgrab/) | Reads a bounded Unicode-text snapshot from the current interactive clipboard. Output can contain credentials or other sensitive values. |
| [`cloudmetadata`](./bofs/sa/cloudmetadata/) | Performs one bounded request against a fixed link-local metadata endpoint. The provider must be selected explicitly. This command does not request AWS IMDSv2 tokens, managed-identity tokens, service-account tokens, or recursive metadata values. |
| [`credentialfiles`](./bofs/sa/credentialfiles/) | Reports the presence and size of common developer, cloud, CI/CD, package, container, and SSH credential files for the current user. It never reads or prints file contents. |
| [`credman`](./bofs/sa/credman/) | Enumerates credentials available to the current logon session through the Windows Credential Manager API and prints bounded credential blobs. |
| [`defenderexclusions`](./bofs/sa/defenderexclusions/) | Enumerates configured path, process, extension, and IP-address exclusions. Registry configuration is reported as configuration evidence, not proof that an exclusion is currently effective. |
| [`dir`](./bofs/sa/dir/) | Lists directory contents with file sizes and timestamps. |
| [`domaininfo`](./bofs/sa/domaininfo/) | Reports local join state and discovers one domain controller, forest name, domain name, and AD site through documented NetAPI calls. |
| [`driveinfo`](./bofs/sa/driveinfo/) | Enumerates logical drives with drive type, volume label, file system, serial number, capacity, and available space. |
| [`driversigs`](./bofs/sa/driversigs/) | Enumerates kernel-mode driver services and checks their binary paths against known EDR/AV vendor signatures. Helps identify security products on the target system. |
| [`enum_filter_driver`](./bofs/sa/enum_filter_driver/) | Enumerates minifilter drivers by scanning the registry for services that have an "Instances" subkey with "Altitude" values. Filter drivers (e.g., antivirus file system filters) register at specific altitudes. |
| [`enumlocalsessions`](./bofs/sa/enumlocalsessions/) | Enumerates all active and disconnected local sessions on the current host using the Windows Terminal Services API (`WTSEnumerateSessionsA`). For each qualifying session, displays the session ID, window station name, domain, and username. |
| [`env`](./bofs/sa/env/) | Lists environment variables visible to the current Beacon process. |
| [`eventchannels`](./bofs/sa/eventchannels/) | Enumerates local Windows Event Log channel names and configured enabled state. An optional case-insensitive substring limits the output. |
| [`findLoadedModule`](./bofs/sa/findLoadedModule/) | Searches all running processes for a specific loaded module (DLL). Enumerates processes via CreateToolhelp32Snapshot and checks each process's module list for a case-insensitive match. |
| [`findfiles`](./bofs/sa/findfiles/) | Searches a directory tree for a case-insensitive wildcard pattern. The maximum depth and result count are mandatory bounds, and reparse points are never traversed. |
| [`get_dpapi_system`](./bofs/sa/get_dpapi_system/) | Retrieves DPAPI system keys from LSA secrets by querying `DPAPI_SYSTEM` and `G$BCKUPKEY_PREFERRED` private data via `LsaRetrievePrivateData`. |
| [`get_netsession`](./bofs/sa/get_netsession/) | Enumerates network sessions on a local or remote computer using NetSessionEnum. |
| [`get_netsession2`](./bofs/sa/get_netsession2/) | Enumerates network sessions with JSON output for BOFHound ingestion. |
| [`get_password_policy`](./bofs/sa/get_password_policy/) | Retrieves the domain password policy and account lockout settings using NetUserModalsGet. Queries level 0 for password requirements and level 3 for lockout configuration. |
| [`get_session_info`](./bofs/sa/get_session_info/) | Retrieves logon session information for the current process token using `LsaGetLogonSessionData`. Displays user name, authentication package, logon type, session ID, logon server, DNS domain, UPN, profile path, home directory, logon time, and password last set. |
| [`ideextensions`](./bofs/sa/ideextensions/) | Enumerates bounded per-user extension directories for common Visual Studio Code-compatible editors and remote editor profiles. It reports directory identities and whether a package manifest exists without reading its content. |
| [`ipconfig`](./bofs/sa/ipconfig/) | Lists local adapter, DNS, gateway, DHCP, and address configuration. |
| [`ldapsearch`](./bofs/sa/ldapsearch/) | Performs LDAP searches against Active Directory using the Windows LDAP API. Supports custom filters, attribute selection, auto-detection of the domain controller via DsGetDcNameA, and automatic base DN discovery via rootDSE. |
| [`ldapsecuritycheck`](./bofs/sa/ldapsecuritycheck/) | Checks LDAP signing and channel binding requirements on a domain controller. Attempts unauthenticated simple binds to determine if LDAP signing is enforced, and tests LDAPS (port 636) connectivity for channel binding assessment. |
| [`list_firewall_rules`](./bofs/sa/list_firewall_rules/) | Enumerates Windows Firewall rules by reading directly from the registry at `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules`. Each value contains a pipe-delimited firewall rule string. Parses and displays Action, Direction, Protocol, Local Port, Remote Port, Application, and Name. |
| [`listdns`](./bofs/sa/listdns/) | Enumerates the local DNS resolver cache entries. |
| [`listmods`](./bofs/sa/listmods/) | Enumerates all loaded modules (DLLs) in a target process using EnumProcessModulesEx and GetModuleFileNameExA. If PID 0 is specified, the current process is used. |
| [`locale`](./bofs/sa/locale/) | Reports the system locale, language, country, and localized date format. |
| [`md5`](./bofs/sa/md5/) | Computes the MD5 hash of a file. |
| [`mdmstatus`](./bofs/sa/mdmstatus/) | Enumerates local Windows MDM enrollment records. A record proves that enrollment data exists; it does not by itself prove that the management channel is currently healthy. |
| [`netgroup`](./bofs/sa/netgroup/) | Lists domain groups and their members using NetQueryDisplayInformation and NetGroupGetUsers Windows API functions. |
| [`netlocalgroup`](./bofs/sa/netlocalgroup/) | Enumerates local groups on a system and optionally lists members of a specific local group using the NetLocalGroupEnum and NetLocalGroupGetMembers Windows API functions. |
| [`netlocalgroup2`](./bofs/sa/netlocalgroup2/) | Enumerates local groups with JSON output for BOFHound ingestion. |
| [`netloggedon`](./bofs/sa/netloggedon/) | Enumerates logged-on users on a local or remote computer using NetWkstaUserEnum. |
| [`netloggedon2`](./bofs/sa/netloggedon2/) | Lists logged-on users with JSON output for BOFHound ingestion. Same functionality as netloggedon but outputs structured JSON. |
| [`netshares`](./bofs/sa/netshares/) | Enumerates network shares on a local or remote computer using NetShareEnum. Supports both admin-level (SHARE_INFO_2) and user-level (SHARE_INFO_1) enumeration. |
| [`netstat`](./bofs/sa/netstat/) | Lists selected local TCP and UDP connection tables with owning process identifiers. |
| [`nettime`](./bofs/sa/nettime/) | Displays the local time on a remote computer using NetRemoteTOD. |
| [`netuptime`](./bofs/sa/netuptime/) | Displays the boot time of a remote computer using NetStatisticsGet. |
| [`netuse`](./bofs/sa/netuse/) | Maps or disconnects network drive connections using WNetAddConnection2A and WNetCancelConnection2A. |
| [`netuser`](./bofs/sa/netuser/) | Gets detailed information for a specific user using NetUserGetInfo (level 2). |
| [`netuserenum`](./bofs/sa/netuserenum/) | Enumerates user accounts on a local or remote computer using NetUserEnum. Supports filtering by account status: all users, locked, disabled, or active. Optionally queries a domain controller via NetGetAnyDCName when targeting a domain. |
| [`netview`](./bofs/sa/netview/) | Enumerates computers on the network using NetServerEnum. |
| [`nonpagedldapsearch`](./bofs/sa/nonpagedldapsearch/) | Performs a simple (non-paged) LDAP search against Active Directory using ldap_search_sA directly. This is a simplified version of ldapsearch that does not use paged result controls. |
| [`notepad`](./bofs/sa/notepad/) | Finds an open Notepad window and reads text from its edit control. |
| [`nslookup`](./bofs/sa/nslookup/) | Performs DNS queries for a domain name using DnsQuery_A. Supports specifying a custom DNS server and record type. |
| [`portscan`](./bofs/sa/portscan/) | Checks a bounded list of TCP ports on one IPv4 address with non-blocking connect and an explicit per-port timeout. It performs no banner grabbing. |
| [`powerstate`](./bofs/sa/powerstate/) | Reports AC and battery state, then classifies the chassis using SMBIOS Type 3 data with a battery-presence fallback. |
| [`probe`](./bofs/sa/probe/) | Checks if a TCP port is open on a target host by attempting a non-blocking connect with a configurable timeout. |
| [`processtokens`](./bofs/sa/processtokens/) | Enumerates accessible process primary tokens and reports the owning account, integrity level, and elevation state. It requests query-only handles. |
| [`proxyenum`](./bofs/sa/proxyenum/) | Reports machine WinHTTP proxy settings, the current user's WinINet proxy and automatic-configuration state, and common proxy environment variables. |
| [`pshistory`](./bofs/sa/pshistory/) | Reads a bounded tail of the current user's PSReadLine console history. Output can contain credentials, tokens, or other sensitive command text. |
| [`reg_query`](./bofs/sa/reg_query/) | Queries the Windows registry for a specific value or enumerates values and subkeys under a given registry path. Supports remote registry access via RegConnectRegistryA when a hostname is provided. |
| [`regsession`](./bofs/sa/regsession/) | Enumerates logged-on user SIDs by inspecting subkeys under HKEY_USERS in the Windows registry. Filters for interactive user SIDs (S-1-5-21-*) and excludes class subkeys (those containing an underscore). Supports remote registry access via `RegConnectRegistryA` when a hostname is provided. |
| [`resources`](./bofs/sa/resources/) | Reports physical-memory use and free and total space for the current drive. |
| [`routeprint`](./bofs/sa/routeprint/) | Lists local network interfaces and the IPv4 routing table. |
| [`sc_qc`](./bofs/sa/sc_qc/) | Queries the configuration of a specific Windows service using QueryServiceConfigA. Displays service type, start type, error control, binary path, load order group, tag, display name, dependencies, and service start name. |
| [`sc_qdescription`](./bofs/sa/sc_qdescription/) | Queries the description of a specific Windows service using QueryServiceConfig2A with SERVICE_CONFIG_DESCRIPTION. |
| [`sc_qfailure`](./bofs/sa/sc_qfailure/) | Queries the failure actions configured for a specific Windows service using QueryServiceConfig2A with SERVICE_CONFIG_FAILURE_ACTIONS (value 2). Displays the reset period, reboot message, command, and each configured failure action with its type and delay. |
| [`sc_qtriggerinfo`](./bofs/sa/sc_qtriggerinfo/) | Queries the trigger information for a specific Windows service using QueryServiceConfig2A with SERVICE_CONFIG_TRIGGER_INFO (value 8). Displays the number of triggers and the type and action of each trigger. |
| [`sc_query`](./bofs/sa/sc_query/) | Queries the status of a specific Windows service or enumerates all services. Displays service type, state, PID, exit codes, and flags. |
| [`schtasksenum`](./bofs/sa/schtasksenum/) | Enumerates all scheduled tasks on a local or remote host by invoking `schtasks /query /fo list` via `CreateProcessA` and capturing the output through an anonymous pipe. |
| [`schtasksquery`](./bofs/sa/schtasksquery/) | Queries a specific scheduled task on a local or remote host by invoking `schtasks /query /tn <taskname> /fo list /v` via `CreateProcessA` and capturing the output through an anonymous pipe. |
| [`sha1`](./bofs/sa/sha1/) | Computes the SHA1 hash of a file. |
| [`sha256`](./bofs/sa/sha256/) | Computes the SHA-256 hash of a file. |
| [`smbinfo`](./bofs/sa/smbinfo/) | Queries a named Windows host through NetWkstaGetInfo and reports its workstation version, platform, computer name, workgroup, and LAN root. |
| [`sysmonstatus`](./bofs/sa/sysmonstatus/) | Reports Sysmon service and driver state, configured binary paths, and the operational event-channel flag without invoking Sysmon itself. |
| [`tasklist`](./bofs/sa/tasklist/) | Enumerates local processes with process ID, parent process ID, session, and image name. |
| [`trayscout`](./bofs/sa/trayscout/) | Reports the taskbar host and bounded Windows 11 notification-area metadata. It does not use undocumented Explorer toolbar structures or read another process's memory. |
| [`uptime`](./bofs/sa/uptime/) | Displays system uptime, current local time, and boot time. |
| [`useridletime`](./bofs/sa/useridletime/) | Displays how long the current user has been idle (no keyboard/mouse input). |
| [`vssenum`](./bofs/sa/vssenum/) | Enumerates Volume Shadow Copies by probing well-known shadow copy device paths (\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN). This avoids COM/WMI dependencies and works by directly testing for the existence of shadow copy volumes using CreateFileA. |
| [`wallpaper`](./bofs/sa/wallpaper/) | Enumerates the current wallpaper path for each desktop monitor through the documented IDesktopWallpaper COM interface. It does not read image files. |
| [`wefstatus`](./bofs/sa/wefstatus/) | Reports Windows Event Collector service state and enumerates local Windows Event Forwarding subscription names through the documented WEC API. |
| [`wevtlogons`](./bofs/sa/wevtlogons/) | Reads a bounded newest-first set of Security events 4624, 4625, and 4672 through Windows Event Log. Security-log access normally requires elevation. |
| [`whoami`](./bofs/sa/whoami/) | Reports the current user, SID, token groups, integrity level, and token privileges. |
| [`windowlist`](./bofs/sa/windowlist/) | Lists top-level desktop window titles and whether each window is visible. |
| [`winver`](./bofs/sa/winver/) | Reports the native Windows version, build, update build revision, product name, display version, and installation type. |
| [`wmi_query`](./bofs/sa/wmi_query/) | Executes a bounded WQL query against a local or remote WMI namespace and prints the returned non-system properties. |
| [`wscstatus`](./bofs/sa/wscstatus/) | Queries aggregate Windows Security Center health for each documented provider category. This reports the state seen by Security Center rather than inferring protection from a process or service name. |

### Remote Operations

| BOF | What it does |
|---|---|
| [`ProcessDestroy`](./bofs/remote/ProcessDestroy/) | Closes a specific handle in a remote process by using `DuplicateHandle` with `DUPLICATE_CLOSE_SOURCE`. This forces the target process to release the specified handle, which can disrupt the process or its dependent resources. |
| [`ProcessListHandles`](./bofs/remote/ProcessListHandles/) | Lists open handles in a target process by calling `NtQuerySystemInformation` with the `SystemHandleInformation` class (16) and filtering results by the specified process ID. For each matching handle, prints the handle value, object type index, and granted access mask. |
| [`adcs_request`](./bofs/remote/adcs_request/) | Enumerates available certificate templates from Active Directory Certificate Services (AD CS) by invoking `certutil -template` via `CreateProcessA` and capturing the output through an anonymous pipe. |
| [`adcs_request_on_behalf`](./bofs/remote/adcs_request_on_behalf/) | Requests a certificate on behalf of another user via an enrollment agent certificate by invoking `certreq` via `CreateProcessA` and capturing the output through an anonymous pipe. |
| [`adduser`](./bofs/remote/adduser/) | Adds a new local user account on a target host using NetUserAdd. |
| [`addusertogroup`](./bofs/remote/addusertogroup/) | Adds a user to a local group using NetLocalGroupAddMembers. |
| [`adsyncdump`](./bofs/remote/adsyncdump/) | Recovers the on-premises Active Directory connector credential from a local Microsoft Entra Connect server. It queries the local ADSync database, reads and DPAPI-decrypts the matching keyset while impersonating `miiserver.exe`, decrypts the connector configuration, and prints the connector username and password. Run from a SYSTEM context on the Entra Connect server. Based on the MIT-licensed ADSyncDump-BOF by Luke Paris (Paradoxis), which in turn references Dirk-jan Mollema's AD Connect research. |
| [`ask_mfa`](./bofs/remote/ask_mfa/) | Displays a fake MFA prompt dialog to the user using `MessageBoxA`. Reports whether the user clicked OK or Cancel for each prompt. |
| [`askcreds`](./bofs/remote/askcreds/) | Displays the native Windows credential dialog and returns the username, domain, and password entered by the interactive user. The dialog does not persist the submitted credential. |
| [`chromeKey`](./bofs/remote/chromeKey/) | Decrypts Chrome's encryption key using CryptUnprotectData (DPAPI). Takes a base64-encoded encrypted key from Chrome's Local State file, strips the "DPAPI" prefix, and decrypts it. |
| [`comprobe`](./bofs/remote/comprobe/) | Tests whether one exact CLSID can be activated with an optional interface identifier and an explicit activation context. The object is immediately released. COM activation can load a DLL or start a local COM server. |
| [`cve_2022_26923`](./bofs/remote/cve_2022_26923/) | Creates, inspects, or removes a machine account in the default Computers container through an authenticated and sealed LDAP session. The create action sets the supplied domain controller name as `dNSHostName`, which is the directory primitive used by CVE-2022-26923 before certificate enrollment. Every mutation is verified and removal is a separate explicit action. |
| [`disableuser`](./bofs/remote/disableuser/) | Disables a user account by setting the UF_ACCOUNTDISABLE flag via NetUserGetInfo (level 1) and NetUserSetInfo (level 1008). |
| [`enableuser`](./bofs/remote/enableuser/) | Enables a user account by clearing the UF_ACCOUNTDISABLE flag via NetUserGetInfo (level 1) and NetUserSetInfo (level 1008). |
| [`eventlog`](./bofs/remote/eventlog/) | Inspects Windows Event Log channels and manages one exact classic custom log through an ownership-checked create, write, clear, and destroy cycle. Arbitrary channel clearing requires an explicit absolute backup path. |
| [`firewallrule`](./bofs/remote/firewallrule/) | Queries, adds, or removes one exact named Windows Firewall rule through INetFwPolicy2. Add refuses a name collision. Remove is the explicit rollback action and should be used only with the exact unique name returned by add. |
| [`get_azure_token`](./bofs/remote/get_azure_token/) | Reads cached Azure/Office OAuth tokens from the Token Broker cache at `%LOCALAPPDATA%\Microsoft\TokenBroker\Cache\`. Enumerates and reads token cache files, printing their contents for offline analysis. |
| [`get_priv`](./bofs/remote/get_priv/) | Enables a specified privilege on the current process or thread token. Prefix privilege name with `~` to target the thread token (useful for impersonated tokens) instead of the process token. |
| [`ghost_task`](./bofs/remote/ghost_task/) | Creates a "ghost" scheduled task by writing directly to the Task Scheduler registry keys, bypassing the Task Scheduler COM API for stealth. Writes a registry key under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<taskname>` with the command stored as a string value. |
| [`global_unprotect`](./bofs/remote/global_unprotect/) | Reads and decrypts GlobalProtect VPN configuration files from `%ProgramData%\Palo Alto Networks\GlobalProtect\`. Searches for portal/gateway config files and decrypts any DPAPI-protected values using CryptUnprotectData. |
| [`lapsdump`](./bofs/remote/lapsdump/) | Queries one computer object for legacy Microsoft LAPS and Windows LAPS attributes using the current security context. Encrypted Windows LAPS data is reported as a bounded hexadecimal preview rather than decrypted. |
| [`lastpass`](./bofs/remote/lastpass/) | Scans browser process memory for LastPass vault data by searching for known patterns such as "lastpass" vault markers and encrypted vault content indicators. Enumerates committed readable memory regions using VirtualQueryEx and reads each with ReadProcessMemory. |
| [`machineaccount`](./bofs/remote/machineaccount/) | Queries, creates, or deletes one exact Active Directory machine account on a named domain controller through NetAPI. Creation refuses to overwrite an existing account. Deletion is a separate explicit rollback action. |
| [`make_token_cert`](./bofs/remote/make_token_cert/) | Imports a PFX certificate file and displays certificate information including the subject name, issuer, serial number, and thumbprint (SHA1). This can be used to verify PFX files for certificate-based authentication. |
| [`nbtscan`](./bofs/remote/nbtscan/) | Sends a bounded NBSTAT query to one IPv4 address or a CIDR containing at most 64 addresses. It reports returned NetBIOS names and MAC addresses. |
| [`office_tokens`](./bofs/remote/office_tokens/) | Scans an Office process's memory for JWT tokens by searching for the base64-encoded JWT prefix "eyJ". Enumerates committed readable memory regions using VirtualQueryEx and reads each with ReadProcessMemory. |
| [`petitpotam`](./bofs/remote/petitpotam/) | Calls the encrypted-file-system RPC interface over the remote `lsarpc` named pipe and supplies a bounded UNC path. `EfsRpcOpenFileRaw` is attempted first and `EfsRpcQueryRecoveryAgents` is used as the protocol-correct fallback. Both calls use Microsoft NDR client contracts. Returned RPC allocations and context handles are released before the BOF exits. |
| [`procdump`](./bofs/remote/procdump/) | Dumps process memory to a file using MiniDumpWriteDump. Enables SeDebugPrivilege before opening the target process so that privileged processes (e.g., lsass.exe) can be dumped. |
| [`reg_delete`](./bofs/remote/reg_delete/) | Deletes a registry value or key. If a value name is provided, deletes just that value using RegDeleteValueA. If the value name is empty, deletes the entire key using RegDeleteKeyA. Supports remote registry access via RegConnectRegistryA when a hostname is provided. |
| [`reg_save`](./bofs/remote/reg_save/) | Saves a registry hive to a file using RegSaveKeyA. Automatically enables SeBackupPrivilege which is required for this operation. Useful for dumping SAM, SECURITY, or SYSTEM hives for offline credential extraction. |
| [`reg_set`](./bofs/remote/reg_set/) | Sets a registry value using RegSetValueExA. Supports remote registry access via RegConnectRegistryA when a hostname is provided. Creates the key if it does not already exist using RegCreateKeyExA. |
| [`sc_config`](./bofs/remote/sc_config/) | Modifies a Windows service's configuration on a local or remote host by connecting to the Service Control Manager (SCM), opening the target service, and calling `ChangeServiceConfigA`. |
| [`sc_create`](./bofs/remote/sc_create/) | Creates a new Windows service on a local or remote host by connecting to the Service Control Manager (SCM) and calling `CreateServiceA`. |
| [`sc_delete`](./bofs/remote/sc_delete/) | Deletes a specified Windows service on a local or remote host by connecting to the Service Control Manager (SCM), opening the target service, and calling `DeleteService`. |
| [`sc_description`](./bofs/remote/sc_description/) | Sets a service's description on a local or remote host by connecting to the Service Control Manager (SCM), opening the target service, and calling `ChangeServiceConfig2A` with `SERVICE_CONFIG_DESCRIPTION`. |
| [`sc_failure`](./bofs/remote/sc_failure/) | Sets service failure recovery actions on a local or remote host by connecting to the Service Control Manager (SCM), opening the target service, and calling `ChangeServiceConfig2A` with `SERVICE_CONFIG_FAILURE_ACTIONS`. |
| [`sc_start`](./bofs/remote/sc_start/) | Starts a specified Windows service on a local or remote host by connecting to the Service Control Manager (SCM), opening the target service, and issuing a start command via `StartServiceA`. |
| [`sc_stop`](./bofs/remote/sc_stop/) | Stops a specified Windows service on a local or remote host by connecting to the Service Control Manager (SCM), opening the target service, querying its current state, and issuing a stop command via `ControlService`. |
| [`schtaskscreate`](./bofs/remote/schtaskscreate/) | Creates a scheduled task on a local or remote host by invoking `schtasks /create /tn <name> /tr <command> /sc once /st 00:00 /f` via `CreateProcessA` and capturing the output through an anonymous pipe. |
| [`schtasksdelete`](./bofs/remote/schtasksdelete/) | Deletes a scheduled task on a local or remote host by invoking `schtasks /delete /tn <name> /f` via `CreateProcessA` and capturing the output through an anonymous pipe. |
| [`schtasksrun`](./bofs/remote/schtasksrun/) | Immediately runs a scheduled task on a local or remote host by invoking `schtasks /run /tn <name>` via `CreateProcessA` and capturing the output through an anonymous pipe. |
| [`schtasksstop`](./bofs/remote/schtasksstop/) | Stops a running scheduled task on a local or remote host by invoking `schtasks /end /tn <name>` via `CreateProcessA` and capturing the output through an anonymous pipe. |
| [`screenshot`](./bofs/remote/screenshot/) | Captures the current virtual desktop through GDI and returns a 32-bit BMP through Beacon's file-transfer protocol. An optional output path supports standalone COFF loaders; the default mode does not create a temporary file. |
| [`setuserpass`](./bofs/remote/setuserpass/) | Changes a user's password using NetUserSetInfo at level 1003. |
| [`shspawnas`](./bofs/remote/shspawnas/) | Spawns a process as another user using `CreateProcessWithLogonW`. |
| [`shutdown`](./bofs/remote/shutdown/) | Shuts down or reboots a local or remote computer using `InitiateSystemShutdownExA`. Enables the appropriate shutdown privilege (`SeShutdownPrivilege` for local, `SeRemoteShutdownPrivilege` for remote) before initiating the shutdown. |
| [`slackKey`](./bofs/remote/slackKey/) | Reads Slack API tokens from local storage files under `%APPDATA%\Slack\storage\`. Searches file contents for token patterns such as "xoxs-", "xoxp-", and "xoxb-". |
| [`slack_cookie`](./bofs/remote/slack_cookie/) | Scans a Slack process's memory for authentication cookies by searching for the "xoxd-" cookie token pattern. Enumerates committed readable memory regions using VirtualQueryEx and reads each with ReadProcessMemory. |
| [`sprayad`](./bofs/remote/sprayad/) | Validates one password against a bounded comma-separated account list with network logons. Successful tokens are closed immediately and no process is created. Incorrect use can lock accounts. |
| [`startwebclient`](./bofs/remote/startwebclient/) | Starts the Windows WebClient service from a standard user context by emitting its documented service-trigger ETW event, then verifies the resulting service state. |
| [`suspendresume`](./bofs/remote/suspendresume/) | Suspends or resumes a target process by PID using the undocumented `NtSuspendProcess` / `NtResumeProcess` NT APIs. Attempts to enable `SeDebugPrivilege` first so that elevated processes can be targeted. |
| [`token`](./bofs/remote/token/) | Creates an impersonation token from explicit credentials, duplicates a token from a selected process, or reverts the current Beacon token. |
| [`unexpireuser`](./bofs/remote/unexpireuser/) | Sets a user account password to never expire by setting the UF_DONT_EXPIRE_PASSWD flag via NetUserGetInfo (level 1) and NetUserSetInfo (level 1008). |

### Injection

| BOF | What it does |
|---|---|
| [`clipboard`](./bofs/injection/clipboard/) | Injects shellcode into a remote process using a clipboard-based target process via `CreateRemoteThread`. `VirtualAllocEx` -> `WriteProcessMemory` -> `VirtualProtectEx` -> clipboard-based technique. |
| [`conhost`](./bofs/injection/conhost/) | Injects shellcode into a remote process using Console Host (conhost.exe) injection. |
| [`createremotethread`](./bofs/injection/createremotethread/) | Injects shellcode into a remote process using the classic `OpenProcess` -> `VirtualAllocEx` -> `WriteProcessMemory` -> `VirtualProtectEx` -> `CreateRemoteThread` technique. |
| [`dde`](./bofs/injection/dde/) | Injects shellcode into a remote process using DDE protocol-based injection. |
| [`kernelcallbacktable`](./bofs/injection/kernelcallbacktable/) | Injects shellcode into a remote process using PEB KernelCallbackTable hijacking. |
| [`ntcreatethread`](./bofs/injection/ntcreatethread/) | Injects shellcode into a remote process using the `OpenProcess` -> `VirtualAllocEx` -> `WriteProcessMemory` -> `VirtualProtectEx` -> `NtCreateThreadEx` technique. |
| [`ntqueueapcthread`](./bofs/injection/ntqueueapcthread/) | Injects shellcode into a remote process using APC queue injection. Allocates memory in the target, writes shellcode, then queues an APC to an alertable thread to trigger execution. |
| [`setthreadcontext`](./bofs/injection/setthreadcontext/) | Injects shellcode into a remote process using thread context hijacking. Suspends a thread, modifies its instruction pointer (RIP) to point at the shellcode, then resumes the thread. |
| [`svcctrl`](./bofs/injection/svcctrl/) | Injects shellcode into a remote process using a service control manager-based injection technique. This variant abuses the SCM to create a temporary service that triggers shellcode execution in the target process. `VirtualAllocEx` -> `WriteProcessMemory` -> `VirtualProtectEx` -> service control-based technique. |
| [`tooltip`](./bofs/injection/tooltip/) | Injects shellcode into a remote process using a tooltip window-based injection technique. This variant locates tooltip windows in the target process and injects shellcode via window message manipulation, abusing the tooltip control's internal data structures. `VirtualAllocEx` -> `WriteProcessMemory` -> `VirtualProtectEx` -> tooltip-based technique. |
| [`uxsubclassinfo`](./bofs/injection/uxsubclassinfo/) | Injects shellcode into a remote process using the UxSubclassInfo window subclass injection technique. This variant manipulates the `UxSubclassInfo` property of a target window to redirect execution flow by overwriting the subclass callback pointer with the address of injected shellcode. `VirtualAllocEx` -> `WriteProcessMemory` -> `VirtualProtectEx` -> UxSubclassInfo-based technique. |

### Kerberos

| BOF | What it does |
|---|---|
| [`asktgs`](./bofs/kerbeus/asktgs/) | Requests a Kerberos service ticket via raw TGS-REQ using an existing TGT. Builds an AP-REQ with encrypted authenticator, sends to KDC port 88, parses TGS-REP, and outputs a base64-encoded .kirbi. |
| [`asktgt`](./bofs/kerbeus/asktgt/) | Requests a Kerberos TGT via raw AS-REQ with pre-authentication. Supports password, RC4 hash, or AES256 hash. Builds the encrypted timestamp PA-DATA using CDLocateCSystem, sends to KDC port 88, parses AS-REP, and outputs a base64-encoded .kirbi. |
| [`askwam`](./bofs/kerbeus/askwam/) | Requests an access token silently through Windows Web Account Manager (WAM) in the current user's context. It can enumerate WAM accounts, select an account by canonical ID or exact username, request v1 resource or v2 scope tokens, and add Continuous Access Evaluation claims. It does not read WAM cache files, show an interactive prompt, or start a worker thread. Based on the MIT-licensed askWAM research by Dirk-jan Mollema. |
| [`asreproasting`](./bofs/kerbeus/asreproasting/) | Requests an AS-REP for users with Kerberos pre-authentication disabled and outputs the encrypted part as a Hashcat-compatible hash for offline cracking. Supports RC4 and AES encryption types. |
| [`changepw`](./bofs/kerbeus/changepw/) | Changes a user password via the MS kpasswd protocol (port 464). First requests a kadmin/changepw service ticket via TGS-REQ, then sends a KRB-PRIV message with the new password. |
| [`cross_s4u`](./bofs/kerbeus/cross_s4u/) | Performs the referral TGT, S4U2Self, and S4U2Proxy request chain for cross-domain constrained delegation across an existing domain trust. |
| [`describe`](./bofs/kerbeus/describe/) | Parses and displays detailed information about a base64-encoded .kirbi ticket (KRB-CRED) using a built-in ASN.1 BER decoder. Shows service name, realm, client name, timestamps, flags, and encryption type. |
| [`dump`](./bofs/kerbeus/dump/) | Exports cached Kerberos tickets as base64-encoded .kirbi blobs via LsaCallAuthenticationPackage with KerbRetrieveEncodedTicketMessage. |
| [`hash`](./bofs/kerbeus/hash/) | Generates Kerberos password hashes (RC4-HMAC, AES128, AES256) from a plaintext password using CDLocateCSystem from cryptdll.dll. AES salts are derived from the domain and username. |
| [`kerberoasting`](./bofs/kerbeus/kerberoasting/) | Requests an SPN service ticket with a supplied TGT and prints the ticket ciphertext as a Hashcat-compatible Kerberoast hash. |
| [`klist`](./bofs/kerbeus/klist/) | Lists cached Kerberos tickets for the current user or all logon sessions if running as SYSTEM via LsaCallAuthenticationPackage. |
| [`ptt`](./bofs/kerbeus/ptt/) | Pass-the-ticket - imports a base64-encoded .kirbi ticket into the current logon session via LsaCallAuthenticationPackage with KerbSubmitTicketMessage. |
| [`purge`](./bofs/kerbeus/purge/) | Purges all cached Kerberos tickets from the current logon session via LsaCallAuthenticationPackage with KerbPurgeTicketCacheMessage. |
| [`renew`](./bofs/kerbeus/renew/) | Renews an existing Kerberos TGT via TGS-REQ with the RENEW flag set. Uses the same AP-REQ construction as asktgs targeting krbtgt. |
| [`s4u`](./bofs/kerbeus/s4u/) | Performs S4U2Self and S4U2Proxy constrained delegation abuse via TGS-REQ with PA-FOR-USER PA-DATA for impersonation. |
| [`tgtdeleg`](./bofs/kerbeus/tgtdeleg/) | Extracts a usable TGT via the Kerberos GSS-API delegation trick. Uses AcquireCredentialsHandle and InitializeSecurityContext with ISC_REQ_DELEGATE to create a delegated AP-REQ containing a KRB-CRED with the user TGT in the authenticator checksum. |
| [`triage`](./bofs/kerbeus/triage/) | Displays a compact table of cached Kerberos tickets showing LUID, client, service, and expiration time. |

### Kernel

| BOF | What it does |
|---|---|
| [`kernel`](./bofs/kernel/) | Uses a separate vulnerable-driver adapter to inspect or change selected Windows kernel and VTL0 process state. The default build has no operational adapter and fails closed for driver-backed actions. |

<!-- BOF_INDEX_END -->

## Building

Requires Git, Rustup, [boflink](https://github.com/MEhrn00/boflink),
[cargo-make](https://github.com/sagiegurari/cargo-make), and MinGW-w64. The
repository pins nightly `2025-01-25`, `rust-src`, and both GNU Windows targets
in `rust-toolchain.toml`.

Clone the reviewed `rustbof` revision into the repository root before building:

```bash
git clone https://github.com/joaoviictorti/rustbof.git
git -C rustbof checkout cab0eabb7cdf816546ba75acfabd91a2b60bba1a
```

Build and link the complete catalog with one command:

```bash
cargo run --manifest-path xtask/Cargo.toml --release -- build-all
```

Each BOF remains an independent crate and can also be built on its own:

```bash
cd bofs/sa/whoami
cargo make
# Output: out/whoami.x64.o
```

The complete build has been validated with MinGW-w64 under WSL. Set `BOFLINK`
when `boflink` is not on `PATH`:

```bash
BOFLINK=/path/to/boflink cargo run --manifest-path xtask/Cargo.toml --release -- build-all
```

Regenerate documentation and rules after changing crate documentation, then
run the release checks against every BOF:

```bash
cargo run --manifest-path xtask/Cargo.toml --release -- generate-assets
cargo run --manifest-path xtask/Cargo.toml --release -- check-release
```

`check-release` verifies the independent-crate layout, crate documentation,
MITRE ATT&CK mappings, README files, YARA rules, publication hygiene, linked
objects, and same-toolchain YARA negative controls. Build outputs and lockfiles
are intentionally ignored.

Use [COFFLoader](https://github.com/trustedsec/COFFLoader) or any compatible loader to test.

No-argument BOFs can be loaded directly with Cobalt Strike's `inline-execute`.
Argument-taking BOFs use the normal Beacon packed-argument ABI. Call them from
an Aggressor Script wrapper with `bof_pack`, or use another compatible runner
that produces the same length-prefixed buffer. Each linked BOF page lists its
argument order and limits. Do not pass a plain command line to a BOF that expects
packed strings or integers.

## Credits and References

- [MITRE ATT&CK](https://attack.mitre.org/) - Adversarial tactics, techniques, and common knowledge framework
- [Microsoft Security Servicing Criteria for Windows](https://www.microsoft.com/msrc/windows-security-servicing-criteria) - Windows security boundaries and servicing criteria
- [Microsoft Symbol Server](https://learn.microsoft.com/windows-hardware/drivers/debugger/microsoft-public-symbols) - Exact Microsoft public symbols
- [Winbindex](https://github.com/m417z/winbindex) - Windows binary version discovery and cross-checking
- [Vergilius Project](https://www.vergiliusproject.com/) - Windows kernel structure reference and cross-checking
- [SigFlip](https://github.com/med0x2e/SigFlip) - Authenticode certificate-table research tooling referenced above
- [LOLDrivers](https://www.loldrivers.io/) - Curated catalog of Windows drivers abused by adversaries; use it to cross-check exact hashes and identities, but absence from the catalog does not prove a driver is safe or allowed
- [rustbof](https://github.com/joaoviictorti/rustbof) by [Joao Victor](https://github.com/joaoviictorti) - Rust BOF framework
- [boflink](https://github.com/MEhrn00/boflink) by [Matt Ehrnschwender](https://github.com/MEhrn00) - Rust static-library to BOF linker
- [UnknownCheats](https://www.unknowncheats.me/) - Public Windows kernel and driver research references
- [Guided Hacking](https://guidedhacking.com/) - Public Windows kernel research and educational references
- [CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF) by [TrustedSec](https://github.com/trustedsec) - Original C BOFs (Situational Awareness)
- [CS-Remote-OPs-BOF](https://github.com/trustedsec/CS-Remote-OPs-BOF) by [TrustedSec](https://github.com/trustedsec) - Original C BOFs (Remote Operations and Injection)
- [Kerbeus-BOF](https://github.com/RalfHacker/Kerbeus-BOF) by [RalfHacker](https://github.com/RalfHacker) - Original C BOFs (Kerberos abuse, Rubeus implementation)
- [Rubeus](https://github.com/GhostPack/Rubeus) by [GhostPack](https://github.com/GhostPack) - Original .NET Kerberos toolset
- [nanorobeus](https://github.com/wavvs/nanorobeus) by [wavvs](https://github.com/wavvs) - Kerberos BOF reference
- [C2-Tool-Collection](https://github.com/outflanknl/C2-Tool-Collection) by [Outflank](https://github.com/outflanknl) - BOF capability and tradecraft reference
- [Extension-Kit](https://github.com/Adaptix-Framework/Extension-Kit) by [Adaptix Framework](https://github.com/Adaptix-Framework) - BOF capability and tradecraft reference
- [Adrenaline](https://github.com/atomiczsec/Adrenaline) by [atomiczsec](https://github.com/atomiczsec) - BOF capability and behavior reference
- [askWAM](https://github.com/dirkjanm/askWAM) by [Dirk-jan Mollema](https://github.com/dirkjanm) - Windows Web Account Manager token research and original BOF behavior reference
- [ADSyncDump-BOF](https://github.com/Paradoxis/ADSyncDump-BOF) by [Luke Paris (Paradoxis)](https://github.com/Paradoxis) - Microsoft Entra Connect credential-recovery behavior reference

## License

MIT. See [LICENSE](./LICENSE)

This repository is designed for malware analysis, reverse engineering,
detection engineering, threat emulation, security research, and controlled
security testing.

The author assumes no responsibility for misuse, damages, or legal consequences arising from the use of this software. Users are solely responsible for ensuring compliance with all applicable laws, regulations, and organizational policies. By using this software, you agree that you have proper authorization for any systems you interact with.

## Author

[memN0ps](https://github.com/memN0ps)
