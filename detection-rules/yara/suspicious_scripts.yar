/*
  SOC Home Lab - YARA Rules: Suspicious Scripts
  Author: Omar Alraas
  Description: Detection rules for obfuscated scripts, reverse shells, and credential harvesters
*/

rule Suspicious_Obfuscated_PowerShell
{
    meta:
        description = "Detects obfuscated PowerShell scripts using common evasion techniques"
        author = "Omar Alraas"
        severity = "high"
        mitre_attack = "T1059.001"
        date = "2025-01-25"

    strings:
        $enc_cmd = "-EncodedCommand" ascii nocase
        $enc_short = "-enc " ascii nocase
        $bypass = "-ExecutionPolicy Bypass" ascii nocase
        $hidden = "-WindowStyle Hidden" ascii nocase
        $noprofile = "-NoProfile" ascii nocase
        $frombase64 = "FromBase64String" ascii nocase
        $decompress = "IO.Compression" ascii nocase
        $reflection = "Reflection.Assembly" ascii nocase
        $download = "DownloadString(" ascii nocase
        $webclient = "Net.WebClient" ascii nocase
        $iex = "IEX(" ascii nocase
        $invoke_expr = "Invoke-Expression" ascii nocase

    condition:
        3 of them
}

rule Suspicious_Base64_Payload
{
    meta:
        description = "Detects large Base64 encoded payloads in script files"
        author = "Omar Alraas"
        severity = "medium"
        mitre_attack = "T1027"
        date = "2025-01-25"

    strings:
        $b64_pattern = /[A-Za-z0-9+\/]{100,}={0,2}/ ascii

    condition:
        #b64_pattern > 0 and filesize < 5MB
}

rule Suspicious_Reverse_Shell_Bash
{
    meta:
        description = "Detects bash reverse shell one-liners"
        author = "Omar Alraas"
        severity = "critical"
        mitre_attack = "T1059.004"
        date = "2025-01-25"

    strings:
        $bash_rs1 = "bash -i >& /dev/tcp/" ascii
        $bash_rs2 = "bash -c 'bash -i" ascii
        $nc_rs1 = "nc -e /bin/sh" ascii
        $nc_rs2 = "nc -e /bin/bash" ascii
        $nc_rs3 = "ncat -e /bin/sh" ascii
        $mkfifo = "mkfifo /tmp/" ascii
        $dev_tcp = "/dev/tcp/" ascii

    condition:
        any of ($bash_rs*) or any of ($nc_rs*) or ($mkfifo and $dev_tcp)
}

rule Suspicious_Reverse_Shell_Python
{
    meta:
        description = "Detects Python reverse shell patterns"
        author = "Omar Alraas"
        severity = "critical"
        mitre_attack = "T1059.006"
        date = "2025-01-25"

    strings:
        $py_socket = "socket.socket" ascii
        $py_connect = ".connect((" ascii
        $py_subprocess = "subprocess" ascii
        $py_pty = "pty.spawn" ascii
        $py_os_dup2 = "os.dup2" ascii
        $py_shell = "/bin/sh" ascii

    condition:
        $py_socket and $py_connect and ($py_subprocess or $py_pty or ($py_os_dup2 and $py_shell))
}

rule Suspicious_Credential_Harvester
{
    meta:
        description = "Detects scripts designed to harvest credentials"
        author = "Omar Alraas"
        severity = "high"
        mitre_attack = "T1003"
        date = "2025-01-25"

    strings:
        $sam = "\\SAM" ascii wide
        $system = "\\SYSTEM" ascii wide
        $security = "\\SECURITY" ascii wide
        $ntds = "ntds.dit" ascii wide nocase
        $lsass = "lsass" ascii wide nocase
        $credential = "credential" ascii wide nocase
        $password = "password" ascii wide nocase
        $dump = "dump" ascii wide nocase
        $extract = "extract" ascii wide nocase

    condition:
        (2 of ($sam, $system, $security)) or
        ($ntds and ($dump or $extract)) or
        ($lsass and ($dump or $credential))
}
