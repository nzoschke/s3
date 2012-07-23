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

def register_scheme(scheme):
  for method in filter(lambda s: s.startswith("uses_"), dir(urlparse)):
    getattr(urlparse, method).append(scheme)

register_scheme("s3")

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
  sys.stderr.write(" ".join(kvs) + "\n")

class S3(object):
  STDERR = sys.stderr
  STDOUT = sys.stdout

  def __init__(self, method, src=None, dest=None, hash=False, url=False, ttl=30):
    self.method = method.upper()
    self.src    = S3.path(src)
    self.dest   = S3.path(dest)
    self.hash   = hash
    self.ttl    = ttl

    d = [p.startswith("s3://") for p in [self.src, self.dest]]
    if method == "GET" and d != [True, False]:
      S3.exit("error: GET must be s3://... => file", 2)
    if method == "PUT" and d != [True, False]:
      S3.exit("error: PUT must be file => s3://...", 2)


  @log
  def get(self, log_ctx=[]):
    return S3.curl("GET", self.dest, S3.signed_url("GET", self.src),  log_ctx)

  @log
  def put(self, log_ctx=[]):
    return S3.curl("PUT", self.src,  S3.signed_url("PUT", self.dest), log_ctx)

  def get_url(self):
    print S3.signed_url("GET", self.src,  self.ttl)

  def put_url(self):
    print S3.signed_url("PUT", self.dest, self.ttl)

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
  def exit(msg, code=1):
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

    m   = re.compile("^(s3://[^\/]+)(.*)").match(p)
    b,p = m.groups()
    return "%s/%s/%s" % (b, k[0], hmac.new(k[1], p, sha).hexdigest())

  @staticmethod
  def path(p):
    d,f = os.path.split(p)
    m   = re.compile("^(\S+)://").match(p)

    if d == "s3:" or f == "" or os.path.isdir(p):
      S3.exit("error: path %s not a file" % p, 2)

    if m:
      if m.group(1) != "s3":
        S3.exit("error: path must use s3:// scheme", 2)
      return p

    p = os.path.abspath(p)
    d,f = os.path.split(p)

    if not os.path.exists(d):
      S3.exit("error: directory %s does not exist" % d, 2)

    return p

  @staticmethod
  def signed_url(method, url, ttl=2, since=None):
    try:
      AWSAccessKeyId      = os.environ["S3_ACCESS_KEY_ID"]
      AWSSecretAccessKey  = os.environ["S3_SECRET_ACCESS_KEY"]
    except KeyError, e:
      S3.exit("error: S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY not set", 2)

    uri     = urlparse.urlparse(url)
    bucket  = uri.hostname
    key     = uri.path[1:]
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
      S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY must be passed via the environment.
      S3_SRC or S3_DEST can be passed instead of --src or --dest.
    """
  )
  subparsers = parser.add_subparsers()
  parser_get = subparsers.add_parser("get")
  parser_put = subparsers.add_parser("put")

  parser_get.add_argument("--src",  help="source URL to GET object", required=True)
  parser_get.add_argument("--dest", help="destination path to write object (default .)", default=".")
  parser_get.add_argument("--url",  help="generate signed URL instead of performing GET", action="store_true")
  parser_get.add_argument("--ttl",  help="signed URL time to live in seconds (default 30)", type=int, default=30)
  parser_get.set_defaults(method="get")

  parser_put.add_argument("--src",  help="source path to read object")
  parser_put.add_argument("--dest", help="destination URL to PUT object (s3://...)", required=True)
  parser_put.add_argument("--url",  help="generate signed URL instead of performing PUT", action="store_true")
  parser_put.add_argument("--ttl",  help="signed URL time to live in seconds (default 30)", type=int, default=30)
  parser_put.set_defaults(method="put")

  # read S3_DEST, S3_SRC args from env
  argv = sys.argv[1:]
  for f in ["dest", "src"]:
    k = "S3_%s" % f.upper()
    if os.environ.get(k):
      argv += ["--%s" % f, os.environ[k]]

  args = parser.parse_args(argv)
  s3 = S3(**vars(args))
