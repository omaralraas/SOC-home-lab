/*
  SOC Home Lab - YARA Rules: Web Shell Detection
  Author: Omar Alraas
  Description: Detection rules for common web shell patterns across PHP, ASP, JSP
*/

rule WebShell_PHP_Generic
{
    meta:
        description = "Detects common PHP web shell patterns"
        author = "Omar Alraas"
        severity = "critical"
        mitre_attack = "T1505.003"
        date = "2025-01-20"

    strings:
        $php_tag = "<?php" ascii nocase
        $eval = "eval(" ascii nocase
        $base64 = "base64_decode(" ascii nocase
        $system = "system(" ascii nocase
        $exec = "exec(" ascii nocase
        $passthru = "passthru(" ascii nocase
        $shell_exec = "shell_exec(" ascii nocase
        $popen = "popen(" ascii nocase
        $proc_open = "proc_open(" ascii nocase
        $assert = "assert(" ascii nocase
        $preg_replace = "preg_replace" ascii nocase
        $create_function = "create_function" ascii nocase
        $gzinflate = "gzinflate(" ascii nocase
        $str_rot13 = "str_rot13(" ascii nocase

    condition:
        $php_tag and (
            ($eval and $base64) or
            ($eval and ($gzinflate or $str_rot13)) or
            (3 of ($system, $exec, $passthru, $shell_exec, $popen, $proc_open)) or
            ($assert and $base64) or
            ($create_function and $base64)
        )
}

rule WebShell_PHP_Known_Signatures
{
    meta:
        description = "Detects known PHP web shell signatures (c99, r57, etc.)"
        author = "Omar Alraas"
        severity = "critical"
        mitre_attack = "T1505.003"
        date = "2025-01-20"

    strings:
        $c99_1 = "c99shell" ascii nocase
        $c99_2 = "c99_buff_prepare" ascii nocase
        $r57_1 = "r57shell" ascii nocase
        $r57_2 = "r57_get_file" ascii nocase
        $wso = "WSO" ascii
        $b374k = "b374k" ascii nocase
        $china_chopper = "eval(Request" ascii nocase
        $weevely = "weevely" ascii nocase

    condition:
        any of them
}

rule WebShell_ASPX_Generic
{
    meta:
        description = "Detects common ASPX web shell patterns"
        author = "Omar Alraas"
        severity = "critical"
        mitre_attack = "T1505.003"
        date = "2025-01-20"

    strings:
        $aspx_tag = "<%@" ascii nocase
        $process_start = "Process.Start" ascii nocase
        $cmd_shell = "cmd.exe" ascii nocase
        $powershell = "powershell" ascii nocase
        $response_write = "Response.Write" ascii nocase
        $request_form = "Request.Form" ascii nocase
        $compile_assembly = "CompileAssemblyFromSource" ascii nocase

    condition:
        $aspx_tag and (
            ($process_start and ($cmd_shell or $powershell)) or
            ($response_write and $request_form and ($cmd_shell or $powershell)) or
            $compile_assembly
        )
}

rule WebShell_JSP_Generic
{
    meta:
        description = "Detects common JSP web shell patterns"
        author = "Omar Alraas"
        severity = "critical"
        mitre_attack = "T1505.003"
        date = "2025-01-20"

    strings:
        $jsp_runtime = "Runtime.getRuntime().exec" ascii
        $jsp_process = "ProcessBuilder" ascii
        $jsp_request = "request.getParameter" ascii
        $jsp_cmd = "/bin/sh" ascii
        $jsp_cmd_win = "cmd.exe" ascii

    condition:
        ($jsp_runtime or $jsp_process) and $jsp_request and ($jsp_cmd or $jsp_cmd_win)
}
