# -*- coding: utf-8 -*-
import ApacheLogParser

if __name__ == '__main__':
    logParser = ApacheLogParser.ApacheLogParser('test/access.log', u"%h %l %u %t %r %s %b \"%{Referer}i\" \"%{User-Agent}i\"")
    logParser.run(3000, 'test.html')
