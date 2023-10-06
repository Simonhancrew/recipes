from dataclasses import dataclass
import dataclasses
import struct
import random
import socket
from io import BytesIO

TYPE_A = 1
CLASS_IN = 1

def env_init():
  random.seed(1)

# dns头，主要是query id，然后4个计数位
@dataclass
class DnsHeader:
  id: int
  flags: int
  num_questions: int = 0
  num_answers: int = 0
  num_authority: int = 0
  num_additional: int = 0

@dataclass
class DnsQuestion:
  name: bytes
  type_: int
  class_: int

@dataclass
class DnsResponse:
  name: bytes
  type_: int
  class_: int
  ttl: int
  data: bytes

def ip_to_string(ips):
  return '.'.join([str(ip) for ip in ips])

# 一共6个字段，每个都是2字节
def headers_to_bytes(header):
  fields = dataclasses.astuple(header)
  return struct.pack('!HHHHHH', *fields)

# name不定长的bytes，然后是type和class，都是2字节
def question_to_bytes(question):
  return question.name + struct.pack("!HH", question.type_, question.class_)

def encode_dns_name(domain_name):
  encoded = b''
  for sec in domain_name.encode('ascii').split(b'.'):
    encoded += bytes([len(sec)]) + sec
  # last char is 0
  return encoded + b'\x00'

def build_query(domain_name, record_type):
  name = encode_dns_name(domain_name)
  id = random.randint(0, 65535)
  print('send id = {}'.format(id))
  RECURSION_DESIRED = 1 << 8
  header = DnsHeader(id=id, num_questions=1, flags=RECURSION_DESIRED)
  question = DnsQuestion(name=name, type_=record_type, class_=CLASS_IN)
  return headers_to_bytes(header) + question_to_bytes(question)


def parse_header(reader):
  items = struct.unpack("!HHHHHH", reader.read(12))
  return DnsHeader(*items)


def decode_compressed_name(length, reader):
  pointer_bytes = bytes([length & 0b0011_1111]) + reader.read(1)
  pointer = struct.unpack("!H", pointer_bytes)[0]
  current_pos = reader.tell()
  reader.seek(pointer)
  result = parse_domain_name(reader)
  reader.seek(current_pos)
  return result

# response里的域名会压缩
def parse_domain_name(reader):
  parts = []
  while (length := reader.read(1)[0]) != 0:
    if length & 0b1100_0000:
      parts.append(decode_compressed_name(length, reader))
      break
    else:
      parts.append(reader.read(length))
  return b'.'.join(parts)

def parse_question(reader):
  name = parse_domain_name(reader)
  data = reader.read(4)
  type_, class_ = struct.unpack("!HH", data)
  return DnsQuestion(name, type_, class_)

def parse_record(reader):
  name = parse_domain_name(reader)
  data = reader.read(10)
  type_, class_, ttl, data_len = struct.unpack("!HHIH", data)
  data = reader.read(data_len)
  print(ip_to_string(data))
  return DnsResponse(name, type_, class_, ttl, data)

def parse_response(response):
  reader = BytesIO(response)
  header = parse_header(reader)
  question = parse_question(reader)
  record = parse_record(reader)
  print(header, question, record)
  
def send_to(query):
  # UDP
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  sock.sendto(query, ('8.8.8.8', 53))
  res, _ = sock.recvfrom(1024)
  return res

if __name__ == '__main__':
  env_init()
  query = build_query('baidu.com', TYPE_A)
  res = send_to(query)  
  parse_response(res)
