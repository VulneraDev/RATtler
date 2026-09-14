/* Original RATtler community rules. Matches are review evidence, not verdicts. */

rule RATtler_Safe_File_Canary : test
{
    meta:
        author = "RATtler contributors"
        license = "MIT"
        description = "Harmless RATtler validation marker detected."
        severity = "info"
        confidence = "test"
    strings:
        $marker = "RATTLER_SAFE_FILE_CANARY_v1" ascii wide
    condition:
        filesize < 1MB and $marker
}

rule RATtler_Heuristic_Script_Downloader_Pipeline : heuristic script
{
    meta:
        author = "RATtler contributors"
        license = "MIT"
        description = "A script combines a network downloader with direct shell execution. Review its source and origin."
        severity = "medium"
        confidence = "heuristic"
    strings:
        $download1 = "curl " ascii nocase
        $download2 = "wget " ascii nocase
        $shell1 = "| sh" ascii nocase
        $shell2 = "| bash" ascii nocase
        $shell3 = "| zsh" ascii nocase
    condition:
        filesize < 5MB and 1 of ($download*) and 1 of ($shell*)
}

rule RATtler_Heuristic_AppleScript_Shell_Dropper : heuristic script macos
{
    meta:
        author = "RATtler contributors"
        license = "MIT"
        description = "AppleScript-style shell execution appears with decoding or downloading behavior."
        severity = "medium"
        confidence = "heuristic"
    strings:
        $applescript = "do shell script" ascii nocase
        $decode1 = "base64 --decode" ascii nocase
        $decode2 = "base64 -D" ascii
        $download1 = "curl " ascii nocase
        $download2 = "URLSession" ascii
    condition:
        filesize < 5MB and $applescript and 1 of ($decode*) and 1 of ($download*)
}

rule RATtler_Heuristic_Keychain_Collection_Script : heuristic script macos
{
    meta:
        author = "RATtler contributors"
        license = "MIT"
        description = "A script contains multiple commands associated with enumerating or exporting macOS keychain data."
        severity = "medium"
        confidence = "heuristic"
    strings:
        $security = "security " ascii nocase
        $find1 = "find-generic-password" ascii nocase
        $find2 = "find-internet-password" ascii nocase
        $dump = "dump-keychain" ascii nocase
        $keychains = "/Library/Keychains" ascii nocase
    condition:
        filesize < 5MB and $security and 2 of ($find*, $dump, $keychains)
}
