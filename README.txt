=====================================
kptool: KeePass v1 DB tool
=====================================

-------------------------
What's this
-------------------------

KeePass version 1 database file access tool that includes access
module.

Currently, support search the entries or groups as the command line
tool.

-------------------------
How to Use
-------------------------

Example: 

::

  % python kptool.py <kdbfilepath>
  password required
  kptool> Ent
  Entry2:
  pass    : entry
  modified: 2010-10-01 22:01:02
  Entry1:
  url     : URL
  pass    : testtest
  modified: 2010-09-26 13:18:13
  kptool> ^D

-------------------------
Building and installation
-------------------------

  % python setup.py install

-------------------------
Testing
-------------------------

  % python setup.py test

-------------------------
Requirement
-------------------------

- Python 2.6 or later
- pyCrypto
- argparse

-------------------------
KeePassdb module API
-------------------------

Constructor(kdbfilepath, masterpassword)
  Create DB from KeePass DB file path and Master password.

  >>> from kptool.keepassdb import keepassdb
  >>> password = u"Hogehoge"
  >>> k = keepassdb.KeepassDBv1("tests/keepass-test.kdb", password)

get_groups()
  Get groups.

  >>> for g in k.get_groups():
  ...   if ('groups' in g):
  ...     print("%s %s in %s" % (g['title'], g['group_id'], g['groups']))
  ...   else:  
  ...     print("%s %s" % (g['title'], g['group_id']))
  Group1 2877859699
  SubGroup1 1203768070 in 2877859699
  Group2 2251441873

get_entries()
  Get entries. 
  Note: KeepassDB has a history. get_entries() get all entries include
  history. Since that, entries that have same title may be acquired.

  >>> for e in k.get_entries():
  ...   print("%s %s %s" % (e['title'], e['username'], e['created']))
  Entry2 entry2 2010-10-01 22:00:51
  SubGroup1 gr 2010-10-01 22:00:29
  Entry1 test 2010-09-26 13:17:55
  日本語です sub 2010-10-01 21:59:33
  Meta-Info SYSTEM 2010-10-01 22:01:04

get_entries_from_groupid(groupid)
  Get entries from groupid. Groupid should be Integer.

  >>> for e in k.get_entries_from_groupid(2877859699):
  ...   print(e['title'])
  Entry1
  Meta-Info

find_groups(searchword)
  Find groups that has <searchword> in title or id.
  
  >>> for g in k.find_groups("up1"):
  ...   print(g['title'])
  Group1
  SubGroup1

find_entries(searchword)
  Find entries that has <searchword> in title, url, comment or username.

  >>> for e in k.find_entries("Ent"):
  ...   print(e['title'])
  Entry2
  Entry1

clear()
  Clears any currently loaded groups and entries in the database.

  >>> k.clear()
  >>> k.get_entries()
  []
  >>> k.get_groups()
  []

*******************
Entry Field Lists
*******************

:id: entry id. String.
:group_id: group id. Integer.
:icon: icon Integer.
:title: title. ASCII or UTF-8
:url: url
:username: username 
:password: password
:comment: comment. ASCII or UTF-8.
:created: created date. Datetime object.
:modifed: modified date. Datetime object.
:accessed: accessed date. Datetime object.
:expires: 
    expires date. Datetime object.
    if "never", shows 2999-12-28 23:59:59.
:bin_desc:
:binary:

*******************
Group Field Lists
*******************
:group_id: group id. Integer.
:title: title
:icon: icon
:level: level. start from 0.
:comment: comment.

-------------------------
BUGS
-------------------------

- Only Rijndael is supported.
- Only passkeys are supported (no key files).
- Only read methods is supported.

-------------------------
TODO
-------------------------

- Write methods.
- KeePass db version 2 support.

-------------------------
License
-------------------------

GPL version2

-------------------------
Acknowledgement
-------------------------

Knowledge about the KeePass DB v1 format was gleaned from the source
code of keepassx-0.4.3 and File::KeePass in the CPAN.

KeePassX 0.4.3 bears the copyright of

  Copyright (C) 2005-2008 Tarek Saidi <tarek.saidi@arcor.de>
  Copyright (C) 2007-2009 Felix Geyer <debfx-keepassx {at} fobos.de>

File::KeePass bears the copyright of 

  Paul Seamons <paul at seamons dot com>
