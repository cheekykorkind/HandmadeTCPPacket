rule tcpRule
{
    strings:
		$hexSourcePort = { 22 b8 }
        $hexDestPort = { 27 0f }
    condition:
        $hexSourcePort and $hexDestPort
}