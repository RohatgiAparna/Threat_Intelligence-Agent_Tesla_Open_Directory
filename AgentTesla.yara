rule AgentTesla
{
    meta:
        description = "AgentTesla_SpyWare"
        os = "Windows"
        maltype = "trojan"
        date = "8/27/2021"

    strings:

        $windows = "This program cannot be run in DOS mode"
        $hash = "46599D29C9831138B75ED7B25049144259139724"       
 	$a4ExeFile = "a4attempt4"
        $publicToken = "b03f5f7f11d50a3a"
    
    condition:
    	uint16(0) == 0x5A4D
        and $windows and $hash and $a4ExeFile and $publicToken
        
}