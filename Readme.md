# s3

Generate signed S3 URLs, and GET/PUT S3 objects via cURL

Dependencies: Python 2.7, and curl binary

## Installation and Usage

```bash
$ curl  -o /usr/local/bin/s3 https://raw.github.com/nzoschke/s3/master/s3.py
$ chmod +x /usr/local/bin/s3

$ s3 -h
usage: s3 [-h] [--file FILE] [--ttl TTL] [--hash] {get,put} s3_url

Generate signed S3 URLs, and GET/PUT S3 objects via cURL

positional arguments:
  {get,put}    perform method
  s3_url       s3://mybucket/path... URL

optional arguments:
  -h, --help   show this help message and exit
  --file FILE  write GET contents to, or read PUT contents from local file
  --ttl TTL    set time to live for URL in seconds (default 30)
  --hash       hash s3_url /path with S3_PATH_KEY

S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY and S3_PATH_KEY must be passed via the
environment. S3_URL or S3_FILE can be passed instead of s3_url or --file.
```

## Examples

```bash
$ export S3_ACCESS_KEY_ID=
$ export S3_SECRET_ACCESS_KEY=

$ s3 put s3://mybucket/s3 --file /usr/local/bin/s3
$ s3 get s3://mybucket/s3 --file /tmp/s3

curl $(s3 get s3://mybucket/s3)
```

## Environment

To minimize shell escape problems, and to keep from leaking information to the 
os process table, s3 accepts arguments as environment variables:

```sh
$ S3_URL=s3://mybucket/s3 S3_FILE=/usr/local/bin/s3 s3 put

$ export S3_URL=S3_URL=s3://mybucket/s3
$ curl $(s3 get)
```

## Secure Keyspace (experimental)

Often the S3 object key encodes information:

    s3://mybucket/backups/nzoschke/22-07-2012.tgz

While this is extremely convenient, it exposes a risk. If an unauthorized
party acquires the AWS keys, he now has access to information about customers in
addition to their data.

One solution is to use UUIDs as keys:

    s3://mybucket/253118c2-d403-11e1-887d-e3e0d8efa6b5

But this requires another stateful service to store the mapping between customer
information and S3 objects, adding operational burden.

s3 offers a solution by managing a keyspace hashed with a secret salt:

```bash
$ export S3_PATH_KEY=v1:584ea019346820869df64694b4dd2556
$ export S3_URL=s3://mybucket/backups/nzoschke/22-07-2012.tgz
$ s3 put --hash
$ s3 get --hash
```

The salt version identifier offers a way to rotate keys and update object paths:

```bash
$ S3_PATH_KEY=v2:462aac410b34973b658d9c7fc426a297 s3 put --hash
```
