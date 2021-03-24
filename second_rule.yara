import "pe"


rule malware_family{
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
    pe.exports("_futurama@4") and
    pe.exports("_hiduk@8") and
    pe.exports("_hockey@4") and
    pe.exports("_husaberg@4") and
    pe.exports("_hyppo@4") and
    pe.exports("_lifan@8") and
    pe.imports("winhttp.dll", "WinHttpCloseHandle") and
    pe.imports("kernel32.dll", "SetEnvironmentVariableW") and
    pe.signature.serial == "04:f1:99:df:c0:5b:d3:4f:34:2f:f5:c2:14:cd:b1:b6:5a:69"
    
}
