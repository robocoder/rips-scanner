#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>
#
# minimal dependencies, we do not require a fully blown html parser, beautifulsoup
#  and others
import sys, re, os

STATS_BEGIN = '<div id="stats" class="stats">'
STATS_END = '<div class="filebox">'

def getargs():
    '''
    minimalistic argparse
    '''
    args = []
    options = []
    if len(sys.argv) <= 1:
        print """Usage: %s [<report.html>, ...]"""%sys.argv[0]
        exit(1)
    for a in sys.argv[1:]:
        if a.startswith("--"):
            options.append(a)
        else:
            args.append(a)
    return args, options

def extract_td_single(column_name,data):
    '''
    utility function to extract data column text
    '''
    d = re.findall(r'%s</td><td[^>]*>([^<]+)'%column_name,data,re.MULTILINE|re.DOTALL)
    if d:
        return d[0]
    return ''

def main(args, options=[]):
    errcode = 0
    stats={}

    for file in args:
        print "[*] processing '%s'"%file
        if not os.path.isfile(file):
            print "[!!] file not found/not a file - '%s'"%file
            continue
        with open(file,'r') as f:
            data = None
            # performance - reduce regex searchspace; extract stats div
            for line in f.readlines():
                if data:
                    data += line
                if STATS_BEGIN in line:
                    data = line[line.index(STATS_BEGIN):]
                    continue
                if STATS_END in line:
                    break
            if data:
                print "[**] extracting data"
                x = re.findall(r'Sum:</td><td>(\d+)</td>', data)
                stats['hits'] = int(x[0]) if x else 0    # if Sum: is missing, there were not vulns.
                stats['cats'] = re.findall(r'catshow\(\'([^\']+)', data)
                stats['num_cats']=len(stats['cats'])
                x = re.findall(r'<span id="scantime">(\d+\.\d+) seconds</span>',data)
                stats['scantime'] = x[0] if x else None

                for s in ("Scanned files:", "Include success:", "Considered sinks:",
                          "User-defined functions:","Unique sources:","Sensitive sinks:"):
                    stats[s] = extract_td_single(s, data).strip()


        stats['dummy']=''
        print "[***] Results"
        print """[    ] Scanned Files:           %(Scanned files:)20s
[    ] Include Success:         %(Include success:)20s
[    ] Time Elapsed:            %(scantime)19ss

[    ] Considered sinks:        %(Considered sinks:)20s
[    ] User-defined functions:  %(User-defined functions:)20s
[    ] Unique sources:          %(Unique sources:)20s
[    ] Sensitive sinks:         %(Sensitive sinks:)20s

[    ] Hits:                    %(hits)20s
[    ] Categories:              %(num_cats)20s"""%stats
        for c in stats.get("cats",[]):
            print "   %50s"%("%s   [+]"%c)
        errcode+=stats.get('hits',0)


    return errcode

if __name__=='__main__':
    args, options = getargs()
    sys.exit(main(args,options))


