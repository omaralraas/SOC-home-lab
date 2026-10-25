/*
  SOC Home Lab - YARA Rules: Ransomware Indicators
  Author: Omar Alraas
  Tests:  tests/yara (compiled with warnings as errors, scanned against
          positive and benign samples)
*/

rule Ransomware_Ransom_Note
{
    meta:
        description = "Ransom note text: payment / decryption language or a Tor payment portal"
        author = "Omar Alraas"
        date = "2025-01-15"
        modified = "2026-10-25"
        severity = "critical"
        mitre_attack = "T1486"

    strings:
        $note1 = "your files have been encrypted" ascii wide nocase
        $note2 = "decrypt your files" ascii wide nocase
        $note3 = "unique decryption key" ascii wide nocase
        $note4 = "do not attempt to decrypt" ascii wide nocase
        $note5 = "payment deadline" ascii wide nocase
        $note6 = "send bitcoin" ascii wide nocase
        $onion = ".onion" ascii wide nocase
        // bech32 addresses: the fixed "bc1" atom keeps this regex fast
        $btc_bech32 = /bc1[qp][a-z0-9]{38,58}/ ascii wide

    condition:
        filesize < 200KB and (2 of ($note*) or ($onion and (1 of ($note*) or $btc_bech32)))
}

rule Ransomware_Recovery_Inhibition_Commands
{
    meta:
        description = "Commands that destroy shadow copies, backups or Windows recovery, embedded in a script or binary"
        author = "Omar Alraas"
        date = "2025-01-15"
        modified = "2026-10-25"
        severity = "critical"
        mitre_attack = "T1490"

    strings:
        $vss1 = "vssadmin delete shadows" ascii wide nocase
        $vss2 = "vssadmin.exe delete shadows" ascii wide nocase
        $vss3 = "resize shadowstorage" ascii wide nocase
        $wmic = "shadowcopy delete" ascii wide nocase
        $wbadmin = "wbadmin delete catalog" ascii wide nocase
        $bcd1 = "recoveryenabled no" ascii wide nocase
        $bcd2 = "bootstatuspolicy ignoreallfailures" ascii wide nocase

    condition:
        any of them
}

rule Ransomware_Binary_Heuristic
{
    meta:
        description = "Windows executable combining file-encryption APIs, recovery inhibition and ransom language"
        author = "Omar Alraas"
        date = "2026-10-25"
        severity = "high"
        mitre_attack = "T1486"

    strings:
        $inhibit1 = "vssadmin" ascii wide nocase
        $inhibit2 = "shadowcopy" ascii wide nocase
        $inhibit3 = "recoveryenabled" ascii wide nocase
        $crypto1 = "CryptEncrypt" ascii
        $crypto2 = "BCryptEncrypt" ascii
        $crypto3 = "CryptGenRandom" ascii
        $crypto4 = "BCryptGenRandom" ascii
        $ransom1 = "decrypt" ascii wide nocase
        $ransom2 = "bitcoin" ascii wide nocase
        $ransom3 = ".onion" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and filesize < 20MB
        and 1 of ($inhibit*) and 1 of ($crypto*) and 1 of ($ransom*)
}
