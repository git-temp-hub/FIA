/*
    DERIVED RULE — modified for memory scanning.

    Original:  HKTL_SentinelOne_RemotePotato0_PrivEsc
    Source:    https://github.com/Neo23x0/signature-base
               yara/gen_remote_potato0.yar
    Author of original: SentinelOne
    Reference: https://labs.sentinelone.com/relaying-potatoes-dce-rpc-ntlm-relay-eop
    Licence:   Detection Rule License (DRL) 1.1

    WHAT WAS CHANGED AND WHY
    ------------------------
    The original condition begins with `uint16(0) == 0x5A4D`, which requires an
    MZ/PE header at offset 0 of the scanned buffer. That holds when scanning a
    file on disk, but a Volatility VAD region is an arbitrary slice of process
    memory, so the guard can effectively never be satisfied and the rule never
    fires against a memory image.

    Only that file-layout guard was removed. Every string and the remaining
    boolean logic is unchanged from the original: all three of $import1,
    $istorage_clsid and $meow_header must still be present, plus at least one
    of the two RemotePotato0 CLSIDs. Four independent required conditions keep
    this specific enough for memory scanning.

    The unmodified original is retained at rules/yara/vendor/gen_remote_potato0.yar
    for provenance; it is compiled alongside this rule but is not expected to
    match memory. The rule name below is deliberately distinct so both can be
    loaded without collision.
*/

rule HKTL_RemotePotato0_PrivEsc_MemoryDerived {
   meta:
      author = "SentinelOne (original); adapted for memory scanning by FIA"
      description = "Detects RemotePotato0 privilege-escalation indicators in process memory"
      original_rule = "HKTL_SentinelOne_RemotePotato0_PrivEsc"
      original_source = "https://github.com/Neo23x0/signature-base"
      reference = "https://labs.sentinelone.com/relaying-potatoes-dce-rpc-ntlm-relay-eop"
      licence = "Detection Rule License 1.1"
      adaptation = "Removed uint16(0)==0x5A4D file-header guard; string logic unchanged"
      date = "2021-04-26"
      severity_guidance = "Treat as a lead requiring corroboration, not a conclusion"
   strings:
      $import1 = "CoGetInstanceFromIStorage"
      $istorage_clsid = "{00000306-0000-0000-c000-000000000046}" nocase wide ascii
      $meow_header = { 4d 45 4f 57 }
      $clsid1 = "{11111111-2222-3333-4444-555555555555}" wide ascii
      $clsid2 = "{5167B42F-C111-47A1-ACC4-8EABE61B0B54}" nocase wide ascii
   condition:
      $import1 and $istorage_clsid and $meow_header and 1 of ($clsid*)
}
