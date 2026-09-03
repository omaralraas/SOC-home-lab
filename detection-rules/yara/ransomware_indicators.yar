/*
  SOC Home Lab - YARA Rules: Ransomware Indicators
  Author: Omar Alraas
  Description: Detection rules for common ransomware behaviors and artifacts
*/

rule Ransomware_Ransom_Note_Strings
{
    meta:
        description = "Detects common ransomware ransom note strings"
        author = "Omar Alraas"
        severity = "critical"
        mitre_attack = "T1486"
        date = "2025-01-15"

    strings:
        $note1 = "Your files have been encrypted" ascii wide nocase
        $note2 = "send bitcoin" ascii wide nocase
        $note3 = "decrypt your files" ascii wide nocase
        $note4 = "payment deadline" ascii wide nocase
        $note5 = "unique decryption key" ascii wide nocase
        $note6 = "DO NOT attempt to decrypt" ascii wide nocase
        $onion = ".onion" ascii wide
        $btc_addr = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii wide

    condition:
        2 of ($note*) or ($onion and $btc_addr) or (3 of them)
}

rule Ransomware_Shadow_Copy_Deletion
{
    meta:
        description = "Detects commands used to delete shadow copies (anti-recovery)"
        author = "Omar Alraas"
        severity = "critical"
        mitre_attack = "T1490"
        date = "2025-01-15"

    strings:
        $cmd1 = "vssadmin delete shadows" ascii wide nocase
        $cmd2 = "vssadmin.exe delete shadows" ascii wide nocase
        $cmd3 = "wmic shadowcopy delete" ascii wide nocase
        $cmd4 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $cmd5 = "wbadmin delete catalog" ascii wide nocase
        $cmd6 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase

    condition:
        any of them
}

rule Ransomware_File_Extension_Pattern
{
    meta:
        description = "Detects files with known ransomware extensions"
        author = "Omar Alraas"
        severity = "high"
        mitre_attack = "T1486"
        date = "2025-01-15"

    strings:
        $ext1 = ".encrypted" ascii
        $ext2 = ".locked" ascii
        $ext3 = ".crypto" ascii
        $ext4 = ".crypt" ascii
        $ext5 = ".enc" ascii
        $ext6 = ".pay2key" ascii
        $ext7 = ".lockbit" ascii
        $ext8 = ".blackcat" ascii

    condition:
        any of them and filesize < 1MB
}
