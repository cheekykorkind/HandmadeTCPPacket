
# -*- coding: utf-8 -*-

import sys
import yara


if __name__ == "__main__":
    print("hi")
    rules = yara.compile(filepath='string_rule.yar')
    print(rules.match('target_file'))
    print('end')