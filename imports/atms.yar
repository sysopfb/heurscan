import "pe"

//rule atm_imports
//{
//condition:
//	pe.imports("dbddevapi.dll") or pe.imports("msxfs.dll")
//}

rule diebold_imports
{
condition:
pe.imports("dbddevapi.dll","DbdDevUnregisterCallback") or
pe.imports("dbddevapi.dll","DbdDevRegisterCallback") or
pe.imports("dbddevapi.dll","DbdDevOpen") or
pe.imports("dbddevapi.dll","DbdDevClose")
}

rule ncr_imports
{
condition:
pe.imports("msxfs.dll","WFSClose") or
pe.imports("msxfs.dll","WFSCleanUp") or
pe.imports("msxfs.dll","WFSExecute") or
pe.imports("msxfs.dll","WFSFreeResult") or
pe.imports("msxfs.dll","WFSStartUp") or
pe.imports("msxfs.dll","WFSGetInfo") or
pe.imports("msxfs.dll","WFSOpen") or
pe.imports("msxfs.dll","WFSFreeResult") or
pe.imports("msxfs.dll","WFSCancelAsyncRequest") or
pe.imports("msxfs.dll","WFSRegister") or
pe.imports("msxfs.dll","WFSAsyncExecute")
}
