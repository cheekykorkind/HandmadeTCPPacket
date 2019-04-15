rule string_rule
{
    strings:
        $a = "hiho" nocase
        // $b = "bibo" nocase
    condition:
        $a
}