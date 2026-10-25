/*
  SOC Home Lab - YARA Rules: Malicious Scripts
  Author: Omar Alraas
  Tests:  tests/yara

  Rules key on combinations of behaviour (fetch or decode, then execute)
  rather than on single keywords, so ordinary admin scripts that merely use
  -NoProfile or Base64 do not match.
*/

rule Suspicious_PowerShell_Loader
{
    meta:
        description = "PowerShell that downloads or decodes content and executes it in memory"
        author = "Omar Alraas"
        date = "2025-01-25"
        modified = "2026-10-25"
        severity = "high"
        mitre_attack = "T1059.001"

    strings:
        $exec1 = "IEX" ascii wide nocase fullword
        $exec2 = "Invoke-Expression" ascii wide nocase
        $exec3 = "Reflection.Assembly]::Load" ascii wide nocase
        $fetch1 = "DownloadString" ascii wide nocase
        $fetch2 = "DownloadData" ascii wide nocase
        $fetch3 = "Net.WebClient" ascii wide nocase
        $fetch4 = "Invoke-WebRequest" ascii wide nocase
        $fetch5 = "Invoke-RestMethod" ascii wide nocase
        $decode1 = "FromBase64String" ascii wide nocase
        $decode2 = "IO.Compression.GzipStream" ascii wide nocase
        $decode3 = "IO.Compression.DeflateStream" ascii wide nocase

    condition:
        filesize < 2MB and 1 of ($exec*) and (1 of ($fetch*) or 1 of ($decode*))
}

rule Suspicious_Decode_And_Execute
{
    meta:
        description = "Script decodes an embedded payload and passes it straight to an eval/exec primitive"
        author = "Omar Alraas"
        date = "2026-10-25"
        severity = "high"
        mitre_attack = "T1027"

    strings:
        $py_dec = "b64decode(" ascii
        $py_exec = /\bexec\s*\(/ ascii
        $js_dec = /\batob\s*\(/ ascii
        $js_eval = /\beval\s*\(/ ascii
        $sh_dec = "base64 -d" ascii
        $sh_pipe1 = "| bash" ascii
        $sh_pipe2 = "|bash" ascii
        $sh_pipe3 = "| sh" ascii fullword

    condition:
        filesize < 1MB and (
            ($py_dec and $py_exec) or
            ($js_dec and $js_eval) or
            ($sh_dec and 1 of ($sh_pipe*))
        )
}

rule Suspicious_Reverse_Shell_Unix
{
    meta:
        description = "Bash / netcat / socat reverse shell one-liners"
        author = "Omar Alraas"
        date = "2025-01-25"
        modified = "2026-10-25"
        severity = "critical"
        mitre_attack = "T1059.004"

    strings:
        $bash1 = "bash -i >& /dev/tcp/" ascii
        $bash2 = "bash -i > /dev/tcp/" ascii
        $bash3 = "0>&1" ascii
        $dev_tcp = "/dev/tcp/" ascii
        $nc1 = "nc -e /bin/sh" ascii
        $nc2 = "nc -e /bin/bash" ascii
        $nc3 = "ncat -e /bin/sh" ascii
        $nc4 = "ncat --exec" ascii
        $mkfifo = "mkfifo /tmp/" ascii
        $nc_plain = "nc " ascii
        $socat = "socat" ascii fullword
        $socat_exec = "exec:/bin/" ascii

    condition:
        filesize < 1MB and (
            $bash1 or $bash2 or ($dev_tcp and $bash3) or
            1 of ($nc1, $nc2, $nc3, $nc4) or
            ($mkfifo and $nc_plain) or
            ($socat and $socat_exec)
        )
}

rule Suspicious_Reverse_Shell_Python
{
    meta:
        description = "Python reverse shell: socket connect wired to a shell via pty or dup2"
        author = "Omar Alraas"
        date = "2025-01-25"
        modified = "2026-10-25"
        severity = "critical"
        mitre_attack = "T1059.006"

    strings:
        $socket = "socket.socket" ascii
        $connect = ".connect((" ascii
        $pty = "pty.spawn" ascii
        $dup2 = "os.dup2" ascii
        $subprocess = "subprocess.call" ascii
        $shell = "/bin/sh" ascii
        $bash = "/bin/bash" ascii

    condition:
        filesize < 1MB and $socket and $connect and ($pty or ($dup2 and ($subprocess or $shell or $bash)))
}

rule Suspicious_Credential_Store_Dump
{
    meta:
        description = "Script that saves the SAM/SYSTEM/SECURITY hives, copies ntds.dit or dumps LSASS"
        author = "Omar Alraas"
        date = "2025-01-25"
        modified = "2026-10-25"
        severity = "critical"
        mitre_attack = "T1003"

    strings:
        $hive_sam = "save hklm\\sam" ascii wide nocase
        $hive_system = "save hklm\\system" ascii wide nocase
        $hive_security = "save hklm\\security" ascii wide nocase
        $ntds1 = "ntdsutil" ascii wide nocase
        $ntds2 = "\\NTDS\\ntds.dit" ascii wide nocase
        $ifm = "ifm" ascii wide nocase fullword
        $lsass1 = "comsvcs.dll, MiniDump" ascii wide nocase
        $lsass2 = "comsvcs.dll MiniDump" ascii wide nocase
        $lsass3 = "sekurlsa::" ascii wide nocase

    condition:
        filesize < 5MB and (
            2 of ($hive*) or
            ($ntds1 and $ifm) or $ntds2 or
            any of ($lsass*)
        )
}
