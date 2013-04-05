#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import getpass
import datetime
import readline

from keepassdb import keepassdb




if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='search entry from keepass DB')
  parser.add_argument('kdb_file',
                      nargs=1,
                      help = 'keepass DB file path')
#  parser.add_argument('--version', action='version', version='%(prog)s 0.1')

  args = parser.parse_args()

  print("Enter password %s" % args.kdb_file)
  password = getpass.getpass()
  try:
    k = keepassdb.KeepassDBv1(args.kdb_file[0], password)
  except ValueError:
    print("Invalid password.")
    exit(1)

  readline.parse_and_bind('tab: complete')
  readline.parse_and_bind('set editing-mode emacs')

  edate = datetime.datetime(2999, 12, 28, 23, 59, 59)

  while True:
    try:
      line = raw_input('kptool> ')
    except EOFError:
      exit(0)
    if line == 'help':
      print("list   : list all entries")
      print("groups : list all groups")
    elif line == 'list':
      ent = []
      for e in k.get_entries():
        if (e['title']) in ent:
          continue
        ent.append((e['title']))
      ent.sort()
      for t in ent:
        print("%s:" % t)
    elif line == 'groups':
      ent = []
      for e in k.get_groups():
        if (e['title']) in ent:
          continue
        ent.append((e['title']))
      ent.sort()
      for t in ent:
        print("%s:" % t)
    else: # normal search
#      for g in k.find_groups(line):
#print("%s " % (g['title']))
      for e in k.find_entries(line):
        print("%s:" % (e['title']))
        if (len(e['url']) > 0):
          print("  url     : %s" % (e['url']))
        print("  pass    : %s" % (e['password']))
        print("  modified: %s" % (e['modified']))
        if (e['expires'] != edate):
          print("  expires : %s" % (e['expires']))

  
