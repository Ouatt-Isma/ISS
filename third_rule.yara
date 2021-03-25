import "pe"
//import "cuckoo"

rule malware_1{
meta:
	description = "Second rule"
		author = " Ismael Ouattara"
		date = " March, 23 2021"
		//sha256 = "915a3b7045e8fc99e2361a3a4c5eae9500f8063d996771f93a96b64dd938eef4"
		strings:
		$dll1 = "kernel32.dll" nocase
		$dll2 = "winhttp.dll" nocase
		condition:
		$dll1 and $dll2 and
		pe.machine == pe.MACHINE_I386 and (pe.characteristics & pe.EXECUTABLE_IMAGE) and
		pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI and
		pe.timestamp == 1586498842 and //pe.entry_point == 0x4d42 and 

		//rich signature is enough
		pe.rich_signature.offset == 0x80 and
		pe.rich_signature.length == 88 and
		pe.rich_signature.key == 0x7BAFAA51 and
		//pe.rich_signature.clear_data == "DanS" //0x536E6144 and

		pe.exports("_futurama@4") and
		pe.exports("_hiduk@8") and
		pe.exports("_hockey@4") and
		pe.exports("_husaberg@4") and
		pe.exports("_hyppo@4") and
		pe.exports("_lifan@8") and
		pe.imports("winhttp.dll", "WinHttpCloseHandle") and
		pe.imports("kernel32.dll", "SetEnvironmentVariableW")

}

rule malware_family_1{
meta:
	description = "Second rule"
		author = " Ismael Ouattara"
		date = " March, 23 2021"
		sha256_1 = "915a3b7045e8fc99e2361a3a4c5eae9500f8063d996771f93a96b64dd938eef4"
		sha256_2 = "bd030578ee9dfbeec78deee6a26ea78137800c5279c2311cb1dab38ccc1dac92"

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


		pe.imports("kernel32.dll", "TlsSetValue") and
		pe.number_of_signatures == 0

		//pe.signatures[0].issuer == "/C=US/CN=R3"
		//pe.signatures[0].serial == "04:f1:99:df:c0:5b:d3:4f:34:2f:f5:c2:14:cd:b1:b6:5a:69"
		//cuckoo.network.host(/195\.201\.225\.248/)
		//35.232.94.42:

}

rule malware_family{
meta:
	description = "fird rule"
		author = " Ismael Ouattara"
		date = " March, 23 2021"

		sha256_1 = "915a3b7045e8fc99e2361a3a4c5eae9500f8063d996771f93a96b64dd938eef4"
		sha256_2 = "bd030578ee9dfbeec78deee6a26ea78137800c5279c2311cb1dab38ccc1dac92"
		sha256_3 = "02990f9b71bb21218c91ab3d5ef6768654988ae5377f946a6041595e120ed0ea"
		sha256_4 = "0f194879fadd2d29f30dafe3e5caeac2dd69bf725a14853ebffde46a5cf170a4"
		sha256_5 = "a660e2d2a31c33b4af1bfeeb29170da58b25c427485e76a238d1af4a0ffe3568"
		sha256_6 = "12eb097562cc5f8b5489e1cb0a2eef7f58e2fe3ba20b11960ee2fcd4f5f0af81"
		sha256_7 = "331de4cbd1605bce9367b649bfda8bda1563fd374610a3e93895f26ab0389f19"
		sha256_8 = "cc77c899048dadecb42238532dff0969e362bfe01cf5507f1462d71ce58360ba"
		sha256_9 = "d56d396970dc35f8b7638fd4c38d831eabd2c4997f1df7e27bc6fdbfedf21c93"
		sha256_10 = "3de56e7b5f730628d7ebb34fa8e147772ac2c1d377379fe4022444d8c2608adb"
		sha256_11 = "64ac4b2d14f86911e01c0bee904ade5fec79e4b6487626c0be4655766ddeb5a0"
		sha256_12 = "e4cbee9b9570fe959b9d06ea44b796bad4e9c25cf96707bb5af3f3212e261e73"
		sha256_13 = "79d0da906de6dc170337e0063c28235fb2e0e86a0c2c73f2701d2b3f56b38c7d"
		//sha256_14 = "385379b365b5a82ad24d2425ad80cbbd2777cd56df5d106cf56e88731aa51080"
		sha256_no = "385379b365b5a82ad24d2425ad80cbbd2777cd56df5d106cf56e88721aa51080"


		strings:
		$dll1 = "kernel32.dll" nocase


		condition:
		$dll1 
		and
		pe.machine == pe.MACHINE_I386 and (pe.characteristics & pe.EXECUTABLE_IMAGE) and
		pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI and
		(
		(
		 pe.exports("Memories") and
		 pe.exports("Roses") and
		 pe.exports("Sos") and
		 pe.exports("Surrender")
		)

		or

		(
		 pe.exports("_futurama@4") and
		 pe.exports("_hiduk@8") and
		 pe.exports("_hockey@4") and
		 pe.exports("_husaberg@4") and
		 //pe.exports("_hyppo@4") and
		 pe.exports("_lifan@8") 
		)
		)
        and
		pe.imports("kernel32.dll", "TlsSetValue") and
		pe.imports("kernel32.dll", "TlsFree") and

		(pe.number_of_signatures == 0 
		 or 
		 (pe.signatures[0].issuer == "/C=US/CN=R3" and
		  pe.signatures[0].serial == "04:f1:99:df:c0:5b:d3:4f:34:2f:f5:c2:14:cd:b1:b6:5a:69")
		)

		//cuckoo.network.host(/195\.201\.225\.248/)
		//35.232.94.42:

}
