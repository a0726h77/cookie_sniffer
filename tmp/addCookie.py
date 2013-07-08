import sqlite3
import re
import sys

conn = sqlite3.connect('.mozilla/firefox/15hpntfs.default/cookies.sqlite')
c = conn.cursor()


# process host and domian of cookies
#host = sys.argv[1]
host = 'wretch.cc'
print host


# process name and value of cookies
cookies = 'Cookie: BX=4nha44444vor4&b=4&s=mj; PHPSESSID=s4tjl4qa4rb44qjudu4ua44pv4; lang=zh-tw\r\n'

p = re.compile('Cookie:(.*=.*)\r\n')
cookies = p.findall(cookies)[0]

cookies = cookies.split(';')



for cookie in cookies:
    name = cookie.split('=')[0].strip()
    value = ''.join(cookie.split('=')[1:])
    print name, value

    c.execute("insert into moz_cookies values(NULL, ?, ?, ?, ?, '/', 1320074857, 1320073057029906, 1320073023832119, 0, 0)", (host, name, value, '.'+host))


conn.commit()

