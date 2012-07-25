#!/usr/bin/env python

import argparse
import base64
import hmac, sha
import inspect
import os
import re
import shutil
from string import Template
import subprocess
import sys
import tempfile
from time import time
import urllib
import urlparse

QUOTABLE = re.compile(r"[\s\\/]")

def log(*data):
  # log() is a decorator if first argument is a function, otherwise a printer
  data = list(data)
  if hasattr(data[0], "__call__"):
    fn = data.pop(0)
    log_ctx = []

    def inner(*args, **kw):
      # The decorator keeps a context of log data. If the function accepts a 
      # log_ctx argument, it can mutate this context.
      if "log_ctx" in inspect.getargspec(fn).args:
        kw["log_ctx"] = log_ctx

      try:
        start = time()
        log(("file", os.path.basename(__file__)), ("fn", fn.__name__), ("at", "start"))
        result = fn(*args, **kw)
        log(("file", os.path.basename(__file__)), ("fn", fn.__name__), ("at", "finish"), ("elapsed", time()-start), *log_ctx)
        return result
      except Exception, e:
        exc = sys.exc_info()
        log(
          ("file", os.path.basename(__file__)), ("fn", fn.__name__), ("at", "error"), 
          ("class", "%s.%s" % (exc[0].__module__, exc[0].__name__)), ("message", exc[1]), ("elapsed", time()-start),
          *log_ctx
        )
        raise exc[0], exc[1], exc[2]
    return inner

  # print data
  kvs = []
  for d in data:
    if isinstance(d, basestring):
        kvs.append(d)
    else:
        s = {
            "dict":     lambda v: "{..",
            "list":     lambda v: "[..",
            "NoneType": lambda v: "none",
            "float":    lambda v: "%.3f" % v,
            "datetime": lambda v: v.isoformat(),
            "date":     lambda v: v.isoformat(),
        }
        v = str(d[1])
        t = type(d[1]).__name__
        if t in s:
            v = s[t](d[1])

        if re.search(QUOTABLE, v):
            v = "\"%s\"" % v.replace("\n", " ")

        kvs.append("%s=%s" % (d[0], v))
  S3.STDERR.write(" ".join(kvs) + "\n")

class S3(object):
  STDERR = sys.stderr
  STDOUT = sys.stdout

  def __init__(self, url, file=None, hash=False, ttl=1):
    r = S3.s3_url(url)
    self.url    = r.geturl()
    self.bucket = r.netloc
    self.path   = r.path

    if file:
      self.file = S3.path(file)

    if hash:
      self.path = S3.hash(self.path)

    self.get_url = S3.signed_url("GET", self.bucket, self.path, ttl)
    self.put_url = S3.signed_url("PUT", self.bucket, self.path, ttl)

  def get(self):
    S3.STDOUT.write(self.get_url + "\n")
    return 0

  def put(self):
    S3.STDOUT.write(self.put_url + "\n")
    return 0

  @log
  def get_file(self, log_ctx=[]):
    code = S3.curl("GET", self.file, self.get_url, log_ctx=log_ctx)
    return 0 if code == 200 else code

  @log
  def put_file(self, log_ctx=[]):
    code = S3.curl("PUT", self.file, self.put_url, log_ctx=log_ctx)
    return 0 if code == 200 else code

  @staticmethod
  def curl(request, path, url, cmd=["curl", "--config", "-"], log_ctx=[]):
    conf = """
      connect-timeout = 5
      dump-header     = "$dump_header"
      max-time        = 60
      request         = "$request"
      retry           = 1
      silent          = "true"
      speed-time      = 30
      speed-limit     = 3000
      write-out       = "code: %{http_code}\\nsize_download: %{size_download}\\nspeed_download: %{speed_download}\\nsize_upload: %{size_upload}\\nspeed_upload: %{speed_upload}\\ntime: %{time_total}"
      url             = "$url"
    """

    if request == "PUT":
      conf += 'upload-file = "$path"'
    else:
      conf += 'output = "$path"'

    with tempfile.NamedTemporaryFile() as header_file:
      conf = Template(conf).substitute(dump_header=header_file.name, path=path, request=request, url=url)
      p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      stdout, stderr = p.communicate(input=conf)

      h = {}
      for line in header_file.readlines() + stdout.split("\n"):
        l = line.split(":", 1)
        if len(l) == 2:
          h[l[0]] = l[1].strip()

    log_ctx += [
      ("path",              urlparse.urlparse(url).path),
      ("x-amz-id-2",        h["x-amz-id-2"]),
      ("x-amz-request-id",  h["x-amz-request-id"]),
      ("code",              int(h["code"])),
      ("size",              int(h["size_download"]) + int(h["size_upload"])),
      ("speed",             float(h["speed_download"]) + float(h["speed_upload"])),
      ("time",              float(h["time"])),
    ]

    if request == "GET" and h["code"] != "200":
      if os.path.exists(path):
        os.remove(path)

    return int(h["code"])

  @staticmethod
  def exit(msg=None, code=1):
    if msg:
      S3.STDERR.write(msg.strip() + "\n")
    sys.exit(code)

  @staticmethod
  def hash(p):
    k = os.environ.get("S3_PATH_KEY")

    if not k:
      S3.exit("error: S3_PATH_KEY not set", 2)

    k = k.split(":", 1)
    if len(k) != 2:
      S3.exit("error: S3_PATH_KEY not in v1:c39c... format", 2)

    return "/%s/%s" % (k[0], hmac.new(k[1], p, sha).hexdigest())

  @staticmethod
  def path(p):
    d,f = os.path.split(p)

    if f == "" or os.path.isdir(p):
      S3.exit("error: path %s not a file" % p, 2)

    p = os.path.abspath(p)
    d,f = os.path.split(p)

    if not os.path.exists(d):
      S3.exit("error: directory %s does not exist" % d, 2)

    return p

  @staticmethod
  def s3_url(url):
    r = urlparse.urlparse(url)
    if r.scheme != "s3" or r.path == "" or r.path.endswith("/"):
      S3.exit("error: url must use s3://bucket/path... scheme", 2)
    return r

  @staticmethod
  def signed_url(method, bucket, path, ttl=2, since=None):
    try:
      AWSAccessKeyId      = os.environ["S3_ACCESS_KEY_ID"]
      AWSSecretAccessKey  = os.environ["S3_SECRET_ACCESS_KEY"]
    except KeyError, e:
      S3.exit("error: S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY not set", 2)

    key     = path[1:]
    since   = since or int(time())
    expires = since + ttl

    canonical_string = "/%s/%s" % (bucket, key)
    stringToSign = method + "\n\n\n" + str(expires) + "\n" + canonical_string
    signature = base64.b64encode(hmac.new(AWSSecretAccessKey, stringToSign, sha).digest())
    return "http://"+bucket+".s3.amazonaws.com/"+urllib.quote(key)+"?AWSAccessKeyId="+urllib.quote(AWSAccessKeyId)+"&Expires="+str(expires)+"&Signature="+urllib.quote(signature)

if __name__ == "__main__":
  parser = argparse.ArgumentParser(
    description="Generate signed S3 URLs, and GET/PUT S3 objects via cURL",
    epilog="""
      S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY and S3_PATH_KEY must be passed via the environment.
      S3_URL or S3_FILE can be passed instead of s3_url or --file.
    """
  )

  parser.add_argument("method",  help="perform method", choices=["get", "put"])
  parser.add_argument("s3_url",  help="s3://mybucket/path... URL")
  parser.add_argument("--file",  help="write GET contents to, or read PUT contents from local file")
  parser.add_argument("--ttl",   help="set time to live for URL in seconds (default 30)", type=int, default=30)
  parser.add_argument("--hash",  help="hash s3_url /path with S3_PATH_KEY", action="store_true")

  argv = sys.argv[1:]

  if os.environ.get("S3_URL"):
    argv += [os.environ["S3_URL"]]

  if os.environ.get("S3_FILE"):
    argv += ["--file", os.environ["S3_FILE"]]

  args = parser.parse_args(argv)

  method  = args.method
  if args.file:
    method += "_file"

  s3 = S3(args.s3_url, file=args.file, hash=args.hash, ttl=args.ttl)
  S3.exit(None, s3.__getattribute__(method)())
