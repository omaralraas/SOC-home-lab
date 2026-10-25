/*
  SOC Home Lab - YARA Rules: Web Shells (PHP, ASPX, JSP)
  Author: Omar Alraas
  Tests:  tests/yara

  Generic rules require attacker-controlled input or a decode chain to reach
  an eval / command-execution sink inside a server-side script, which is what
  separates a web shell from ordinary code that happens to call exec().
  Wazuh FIM watches /var/www (wazuh/shared/agent.conf), so new or changed
  files there can be scanned with these rules during triage.
*/

rule WebShell_PHP_Generic
{
    meta:
        description = "PHP that feeds request input or a decoded blob into eval/assert, or request input into a command sink"
        author = "Omar Alraas"
        date = "2025-01-20"
        modified = "2026-10-25"
        severity = "critical"
        mitre_attack = "T1505.003"

    strings:
        $php1 = "<?php" ascii nocase
        $php2 = "<?=" ascii
        $in1 = "$_POST" ascii
        $in2 = "$_GET" ascii
        $in3 = "$_REQUEST" ascii
        $in4 = "$_COOKIE" ascii
        $in5 = "php://input" ascii
        $eval1 = /\beval\s*\(/ ascii nocase
        $eval2 = /\bassert\s*\(/ ascii nocase
        $eval3 = /\bcreate_function\s*\(/ ascii nocase
        $dec1 = "base64_decode(" ascii nocase
        $dec2 = "gzinflate(" ascii nocase
        $dec3 = "str_rot13(" ascii nocase
        $dec4 = "gzuncompress(" ascii nocase
        $cmd1 = /\bsystem\s*\(/ ascii nocase
        $cmd2 = /\bpassthru\s*\(/ ascii nocase
        $cmd3 = /\bshell_exec\s*\(/ ascii nocase
        $cmd4 = /\bpopen\s*\(/ ascii nocase
        $cmd5 = /\bproc_open\s*\(/ ascii nocase
        $cmd6 = /\bpcntl_exec\s*\(/ ascii nocase

    condition:
        1 of ($php*) and filesize < 1MB and (
            (1 of ($eval*) and (1 of ($in*) or 1 of ($dec*))) or
            (1 of ($cmd*) and 1 of ($in*))
        )
}

rule WebShell_Known_Families
{
    meta:
        description = "Markers of well-known PHP web shell families (c99, r57, b374k, WSO)"
        author = "Omar Alraas"
        date = "2025-01-20"
        modified = "2026-10-25"
        severity = "critical"
        mitre_attack = "T1505.003"

    strings:
        $php = "<?php" ascii nocase
        $c99_1 = "c99shell" ascii nocase
        $c99_2 = "c99_buff_prepare" ascii nocase
        $r57_1 = "r57shell" ascii nocase
        $r57_2 = "r57_get_file" ascii nocase
        $b374k = "b374k" ascii nocase
        $wso = "FilesMan" ascii

    condition:
        $php and filesize < 2MB and any of ($c99*, $r57*, $b374k, $wso)
}

rule WebShell_ASPX_Generic
{
    meta:
        description = "ASP.NET page that runs commands or compiles code from request input (incl. China Chopper)"
        author = "Omar Alraas"
        date = "2025-01-20"
        modified = "2026-10-25"
        severity = "critical"
        mitre_attack = "T1505.003"

    strings:
        $tag = "<%@" ascii nocase
        $tag_chopper = "<%" ascii
        $proc = "Process.Start" ascii nocase
        $psi = "ProcessStartInfo" ascii nocase
        $cmd = "cmd.exe" ascii nocase
        $ps = "powershell" ascii nocase
        $req1 = "Request.Form" ascii nocase
        $req2 = "Request.QueryString" ascii nocase
        $req3 = "Request.Item" ascii nocase
        $compile = "CompileAssemblyFromSource" ascii nocase
        $chopper = "eval(Request" ascii nocase

    condition:
        filesize < 1MB and (
            ($tag and ($proc or $psi) and ($cmd or $ps) and 1 of ($req*)) or
            ($tag and $compile) or
            ($tag_chopper and $chopper)
        )
}

rule WebShell_JSP_Generic
{
    meta:
        description = "JSP page that executes an OS command taken from a request parameter"
        author = "Omar Alraas"
        date = "2025-01-20"
        modified = "2026-10-25"
        severity = "critical"
        mitre_attack = "T1505.003"

    strings:
        $exec1 = "Runtime.getRuntime().exec" ascii
        $exec2 = "ProcessBuilder" ascii
        $param = "request.getParameter" ascii

    condition:
        filesize < 1MB and 1 of ($exec*) and $param
}
