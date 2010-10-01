#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import getpass

from keepassdb import keepassdb


if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='search entry from keepass DB')
  parser.add_argument('-f',
		      '--kdb-file',
		      help = 'keepass DB file path',
		      required=True, )
  parser.add_argument('entry_title')
#  parser.add_argument('--version', action='version', version='%(prog)s 0.1')

  args = parser.parse_args() 

  print("enter password for %s" % args.kdb_file)
  password = getpass.getpass()
  #password = "Hogehoge"
  k = keepassdb.KeepassDBv1(args.kdb_file, password)

  for g in k.find_groups(args.entry_title):
    print("%s " % (g['title']))
  for e in k.find_entries(args.entry_title):
    print("%s -> %s (%s)" % (e['title'], e['password'], e['expires']))
  
