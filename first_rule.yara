import "pe"


rule malware_1{
  meta:
    description = "Second rule"
    author = " Ismael Ouattara"
    date = " March, 23 2021"
    sha256 = "915a3b7045e8fc99e2361a3a4c5eae9500f8063d996771f93a96b64dd938eef4"
  strings:
    $dll1 = "kernel32.dll" nocase
    $dll2 = "winhttp.dll" nocase
  condition:
    $dll1 and $dll2 and
    pe.machine == pe.MACHINE_I386 and (pe.characteristics & pe.EXECUTABLE_IMAGE) and
    pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI and
    //pe.timestamp == 1586498842 //and pe.entry_point == 0x4d42 and 

    pe.rich_signature.offset == 0x80 and
    pe.rich_signature.length == 88 and
    pe.rich_signature.key == 0x7BAFAA51 and
    //pe.rich_signature.clear_data == "DanS" //0x536E6144
    /*
    pe.exports("_futurama@4") and
    pe.exports("_hiduk@8") and
    pe.exports("_hockey@4") and
    pe.exports("_husaberg@4") and
    pe.exports("_hyppo@4") and
    pe.exports("_lifan@8") and
    pe.imports("winhttp.dll", "WinHttpCloseHandle") and
    pe.imports("kernel32.dll", "SetEnvironmentVariableW")
    */
}
