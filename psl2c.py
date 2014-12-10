#!/usr/bin/python

import urllib
import time

PSLURL='https://publicsuffix.org/list/effective_tld_names.dat'
PUBLICSUFFIX_H='services/publicsuffix.h'

def str2rule(str):
    str = str.rstrip()
    str = str.lstrip()
    i = str.find('//')

    if i >= 0:
        str = str[:i]

    str = str.rstrip()
    str = str.lstrip()
    if len(str) == 0:
        return None
    return str


def psl2c():
    f = urllib.urlopen(PSLURL)
    psl = []
    ilines = []
    lines = f.readlines()
    icann = False
    
    for s in lines:
        if s.find('==BEGIN ICANN DOMAINS==') >= 0:
            icann = True
        if s.find('==END ICANN DOMAINS==') >= 0:
            icann = False
        if icann:
            ilines.append(s)

    if len(ilines) > 0:
        lines = ilines

    for s in lines:
        s = s.decode('utf-8')
        s = str2rule(s)
        if s:
            psl.append('\t"' + s.encode('idna')+ '"')
    f = open(PUBLICSUFFIX_H, "w")
    f.write('/* taken from %s */\n' % PSLURL)
    f.write('/* at %s UTC */\n' % time.asctime(time.gmtime()))
    f.write('#ifndef SERVICES_PUBLICSUFFIXLIST_H\n')
    f.write('#define SERVICES_PUBLICSUFFIXLIST_H\n')
    f.write('static char *publicsuffix[] = {\n')
    f.write(',\n'.join(psl))
    f.write('\n};\n')
    f.write('#endif /* SERVICES_PUBLICSUFFIXLIST_H */\n')
if __name__ == '__main__':
    psl2c()

