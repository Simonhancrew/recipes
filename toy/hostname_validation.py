import re

"""
  Match a hostname against a wildcard pattern. Just a simple example
  Support domains only, ip are not supported.
  E.g.
  "foo.host.com" matches "*.host.com".

  We use the matching rule described in RFC6125, section 6.4.3.
  http://tools.ietf.org/html/rfc6125#section-6.4.3
"""


def match_hostname(hostname, pattern):
    if re.match(r"\A" + re.escape(pattern).replace(r"\*", r"[^.]*") + r"\Z", hostname):
        print("{} match {}".format(hostname, pattern))
        return
    print("{} doesn't match {}".format(hostname, pattern))
