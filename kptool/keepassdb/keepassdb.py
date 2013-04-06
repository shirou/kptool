#!/usr/bin/env python
# -*- coding: utf-8 -*-


import struct
from Crypto.Cipher import AES
import hashlib
from binascii import * # for entry id
import datetime

DB_HEADER_SIZE   = 124
DB_SIG_1         = 0x9AA2D903
DB_SIG_2         = 0xB54BFB65
DB_VER_DW        = 0x00030002
DB_FLAG_SHA2     = 1
DB_FLAG_RIJNDAEL = 2
DB_FLAG_ARCFOUR  = 4
DB_FLAG_TWOFISH  = 8


def parse_null_turminated(a_string):
    """
    Strips the first null byte '\x00' from the given argument and returns a
    string/unicode object. Works on strings in python 2 and on byte strings
    in python 3.
    """
    a_string = a_string.replace('\x00'.encode('utf8'), ''.encode('utf8'))
    return a_string.decode('utf8')


class Header:
  def __init__(self, field):
    self.sig1, self.sig2, self.flags, self.ver, self.seed_rand, self.enc_iv, self.n_groups, self.n_entries, self.checksum, self.seed_key, self.seed_rot_n = field

class KeepassDBv1:
  """
  keepass v1 password database handling module.
  currently, can only read access.
  """

  def __init__(self, filepath, masterpass):
    self.load_db(filepath, masterpass)

  def load_db(self, filepath, masterpass):
    f = open(filepath, "rb")
    buf = f.read()
    f.close()
    self.db = self.parse_db(buf, masterpass)

  def parse_db(self, buf, masterpass):
    self.header = self.parse_header(buf)
    if (self.header.sig1 != DB_SIG_1):
      raise ValueError("Invalid Signature 1")
    if (self.header.sig2 != DB_SIG_2):
      raise ValueError("Invalid Signature 2")
    if (self.header.ver & 0xFFFFFF00 != DB_VER_DW & 0xFFFFFF00):
      raise ValueError("Unsupported File Version")

    if (self.header.flags & DB_FLAG_RIJNDAEL):
      self.enc_type = 'rijndael'
    elif (self.header.flags & DB_FLAG_TWOFISH):
      self.enc_type = 'twofish'
    else:
      raise ValueError("Unknown Encryption Algorithm.")

    # remove header from buffer
    buf = buf[DB_HEADER_SIZE:]

    # create key
    key = hashlib.sha256(masterpass.encode('utf8')).digest()
    self.cipher = AES.new(self.header.seed_key,  AES.MODE_ECB)
    for i in range(0, self.header.seed_rot_n):
      key = self.cipher.encrypt(key)
    key = hashlib.sha256(key).digest()
    finalkey = hashlib.sha256(self.header.seed_rand + key).digest()

    # decrypt! 
    crypto_size = 0
    if ('rijndael' in self.enc_type):
      buf = self.decrypt_aes_cbc(buf, finalkey, self.header.enc_iv)
      crypto_size = len(buf)

    if ((crypto_size > 2147483446) or (not crypto_size and self.header.n_groups)):
      raise ValueError("Decryption failed.\nThe key is wrong or the file is damaged")

    if self.header.checksum != hashlib.sha256(buf).digest():
      raise ValueError("Decryption failed. The file checksum did not match.")

    # parse and create groups and entries
    self.groups = []
    self.entries = []
    (groups, pos) = self.parse_groups(buf, self.header.n_groups)
    entries = self.parse_entries(buf, self.header.n_entries, pos, groups)

    # parse done
    self.entries = entries
    self.groups  = groups
    self.lock    = True

    return 1

  def parse_groups(self, buf, n_groups):
    pos = 0
    previous_level = 0
    previous_groupid = -1
    groups = []
    group = {}
    while(n_groups):
      m_type = struct.unpack("<H", buf[pos:pos+2])[0]
      pos += 2
      if pos >= len(buf):
        raise ValueError("Group header offset is out of range. ($pos)")
      size = struct.unpack("<L", buf[pos:pos+4])[0]
      pos += 4
      if (pos + size) > len(buf):
        raise ValueError("Group header offset is out of range. ($pos, $size)")
      if (m_type == 1):
        group['group_id'] = struct.unpack("<L", buf[pos:pos+4])[0]
      elif (m_type == 2):
        group['title'] = parse_null_turminated(buf[pos:pos+size])
      elif (m_type == 7):
        group['icon'] = struct.unpack("<L", buf[pos:pos+4])[0]
      elif (m_type == 8):
        group['level'] = struct.unpack("<H", buf[pos:pos+2])[0]
      elif (m_type == 0xFFFF): # end of a group
        n_groups -= 1
        if ('level' in group):
          level = group['level']
        else:
          level = 0
        if (previous_level < level):
          if (self.is_group_exists(groups, previous_groupid)):
            group['groups'] = previous_groupid
          
        previous_level = level
        previous_groupid = int(group['group_id'])
        groups.append(group)
        group = {}
      else:
        group['unknown'] = buf[pos:pos+size]
        
      pos += size;

    return groups, pos

  def parse_entries(self, buf, n_entries, pos, groups):
    entry = {}
    entries = []
    while(n_entries):
      m_type = struct.unpack("<H", buf[pos:pos+2])[0]
      pos += 2;
      if pos >= len(buf):
        raise ValueError("Entry header offset is out of range. ($pos)")
      size = struct.unpack('<L', buf[pos:pos+4])[0]
      pos += 4
      if (pos + size) > len(buf):
        raise ValueError("Entry header offset is out of range. ($pos, $size)" )
      if (m_type == 1):
        entry['id'] = parse_null_turminated(b2a_hex(buf[pos:pos+size]))
      elif (m_type == 2):
        entry['group_id'] = struct.unpack('<L', buf[pos:pos+4])[0]
      elif (m_type == 3):
        entry['icon'] = struct.unpack('<L', buf[pos:pos+4])[0]
      elif (m_type == 4):
        entry['title'] = parse_null_turminated(buf[pos:pos+size])
      elif (m_type == 5):
        entry['url'] = parse_null_turminated(buf[pos:pos+size])
      elif (m_type == 6):
        entry['username'] = parse_null_turminated(buf[pos:pos+size])
      elif (m_type == 7):
        entry['password'] = parse_null_turminated(buf[pos:pos+size])
      elif (m_type == 8):
        entry['comment'] = parse_null_turminated(buf[pos:pos+size])
      elif (m_type == 9):
        entry['created'] = self.parse_date(buf, pos, size)
      elif (m_type == 0xA):
        entry['modified'] = self.parse_date(buf, pos, size)
      elif (m_type == 0xB):
        entry['accessed'] = self.parse_date(buf, pos, size)
      elif (m_type == 0xC):
        entry['expires'] = self.parse_date(buf, pos, size)
      elif (m_type == 0xD):
        entry['bin_desc'] = parse_null_turminated(buf[pos:pos+size])
      elif (m_type == 0xE):
        entry['binary'] = buf[pos:pos+size]
      elif (m_type == 0xFFFF): # end of a entry
        n_entries -= 1
        
        # orphaned nodes go into the special group
        if not self.is_group_exists(groups, entry['group_id']):
          if (not self.is_group_exists(groups, -1)):
            group = {}
            group['group_id'] = -1
            group['title'] = "*Orphaned*"
            group['icon']  = 0
            groups.append(group)
          entry['group_id'] = -1

        if ('comment' in entry and entry['comment'] == 'KPX_GROUP_TREE_STATE'):
          if (not 'binary' in entry or len(entry['binary']) < 4):
              raise ValueError("Discarded metastream KPX_GROUP_TREE_STATE because of a parsing error.")
          n = struct.unpack('<L', entry['binary'][:4])[0]
          if (n * 5 != len(entry['binary']) - 4):
            raise ValueError("Discarded metastream KPX_GROUP_TREE_STATE because of a parsing binary error.")
          else:
            for i in range(0,n):
              s = 4+i*5
              e = 4+i*5 + 4
              group_id = struct.unpack('<L', entry['binary'][s:e])[0]
              s = 8+i*5
              e = 8+i*5 + 1
              is_expanded = struct.unpack('B', entry['binary'][s:e])[0]
              for g in groups:
                if (g['group_id'] == group_id):
                  g['expanded'] = is_expanded
        else:
          entries.append(entry)
        entry = {}
      else:
        entry['unknown'] = buf[pos:pos+size]
        
      pos += size;

    return entries

  def parse_date(self, buf, pos, size):
    b = struct.unpack('<5B', buf[pos:pos+size])
    year = (b[0] << 6) | (b[1] >> 2);
    mon  = ((b[1] & 0b11)     << 2) | (b[2] >> 6);
    day  = ((b[2] & 0b111111) >> 1);
    hour = ((b[2] & 0b1)      << 4) | (b[3] >> 4);
    min  = ((b[3] & 0b1111)   << 2) | (b[4] >> 6);
    sec  = ((b[4] & 0b111111));

    return datetime.datetime(year, mon, day, hour, min, sec)
    # return "%04d-%02d-%02d %02d:%02d:%02d" % (year, mon, day, hour, min, sec)

  def clear(self):
    del self.groups[:]
    del self.entries[:]

  def parse_header(self, buf):
    size = len(buf)
    if (size < DB_HEADER_SIZE):
      raise ValueError("file size is too small")

    format = '<L L L L 16s 16s L L 32s 32s L'
    # sig1 sig2 flags ver seed_rand enc_iv n_groups n_entries checksum seed_key seed_rot_n);
    field = struct.unpack(format, buf[0:DB_HEADER_SIZE])
    return Header(field)

  def decrypt_aes_cbc(self, buf, key, enc_iv):
    cipher = AES.new(key, AES.MODE_CBC, enc_iv)
    buf = cipher.decrypt(buf)

    extra = buf[-1]
    if not isinstance(extra, int):
        # In python 2, the crypto stuff works on strings, not byte arrays
        extra = ord(extra)

    buf = buf[:len(buf)-extra] # last len(extra) becomes blank
    
    return buf
  
  def encrypt_rijndael_cbc(self, buf, key, enc_iv):
    cipher = AES.new(key, AES.MODE_CBC, enc_iv)
    return cipher.encrypt(buf)

  def header(self):
    return self.header

  def is_locked(self):
    return self.lock

  def lock(self):
    if (self.lock == True):
      raise ValueError("already locked")
    self.lock = True
  
  def unlock(self):
    self.lock = False
  
  def is_entry_include_word(self, entry, word):
    if (word in entry['title']):
      return True
    elif (word in entry['id']):
      return True
    elif (word in entry['url']):
      return True
    elif (word in entry['comment']):
      return True
    elif (word in entry['username']):
      return True
    return False
  
  def is_group_exists(self, groups, group_id):
    for g in groups:
      if (g['group_id'] == group_id):
        return True
    return False
  
  def is_group_include_word(self, group, word):
    if (word in group['title']):
      return True
    if (word == group['group_id']):
      return True
    return False

  def get_groups(self):
    return self.groups
  def get_entries(self):
    return self.entries

  def get_entries_from_groupid(self, groupid):
    result = []

    [ result.append(e) for e in self.entries if e['group_id'] == groupid ]
    return result

  def find_groups(self, word):
    result = []
    [ result.append(g) for g in self.groups if self.is_group_include_word(g, word) ]
    return result

  def find_entries(self, word):
    result = []

    [ result.append(e) for e in self.entries if self.is_entry_include_word(e, word) ]
    return result

if __name__ == '__main__':
  password = "Hogehoge"
  k = Keepassv1("keepass-test.kdb",password)

  # print(k.groups)
  #  print(k.entries)
  print(k.find_groups(title="Group1"))
  print(k.find_entries("Entry1"))
