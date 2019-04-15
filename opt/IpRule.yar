rule IpRule
{
    strings:
        $hexSourceIp = { 01 23 45 67 89 ab cd ef }
		$hexDestIp = { 01 23 45 67 89 ab cd ef }
    condition:
        $hexSourceIp and $hexDestIp
}