import re
pat = re.compile(r"(?<![\w-])(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?![\w-])")
print(pat.findall("slack_token = xoxb-1234567890-1234567890-abcdefghij"))
print(pat.findall("call me at 123-456-7890 please"))
print(pat.findall("or +1 (555) 123-4567."))
