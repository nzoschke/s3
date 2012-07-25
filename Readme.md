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
$ export bucket=mybucket
$ export S3_ACCESS_KEY_ID=AKI...
$ export S3_SECRET_ACCESS_KEY=

$ s3 put s3://$bucket/s3
http://mybucket.s3.amazonaws.com/s3?AWSAccessKeyId=AKI...&Expires=1343251897&Signature=HSL556B4lYs1Aqiw5Gsw%2BjR2/HM%3D

$ s3 put s3://$bucket/s3 --file /usr/local/bin/s3
file=s3 fn=put_file at=start
file=s3 fn=put_file at=finish elapsed=0.946 path="/s3" x-amz-id-2="eT4xqDJ51Rw7FLRdLa0tfi75222KTl8ThnLy1kFph7lIxr6u2Zdjbuzg3vIFnZw/" x-amz-request-id=F41C47F14BAAAE96 code=200 size=7581 speed=8142.000 time=0.931

$ s3 get s3://$bucket/s3 --file /tmp/s3
file=s3 fn=get_file at=start
file=s3 fn=get_file at=finish elapsed=0.300 path="/s3" x-amz-id-2="u1RAuEbMl8RE0bae2+7BhzBzhM2xri6j3/VRsnC65DvZV4pB1uJ97XxBEQy7zCYQ" x-amz-request-id=131E48751201F491 code=200 size=7581 speed=26400.000 time=0.287

$ curl $(s3 get s3://$bucket/s3)
#!/usr/bin/env python

import argparse
...

$ curl --request PUT --upload-file /tmp/s3 $(s3 put s3://$bucket/s3)

```

## Environment

To minimize shell escape problems, and to keep from leaking information to the 
os process table, s3 accepts arguments as environment variables:

```sh
$ S3_URL=s3://$bucket/s3 S3_FILE=/usr/local/bin/s3 s3 put

$ export S3_URL=s3://$bucket/s3
$ curl $(s3 get)
```

## Secure Keyspace (experimental)

Often the S3 object key encodes information:

    s3://mybucket/backups/nzoschke/22-07-2012.tgz

While this is extremely convenient, it exposes a possible increased risk. If an
unauthorized party acquires the AWS keys, he now has quick access to information 
about customers in addition to their data.

One solution is to use UUIDs as keys:

    s3://mybucket/253118c2-d403-11e1-887d-e3e0d8efa6b5

But this requires another stateful service to store the mapping between customer
information and S3 objects, adding operational burden.

s3 offers a solution by managing a keyspace hashed with a secret salt:

```bash
$ export S3_PATH_KEY=v1:584ea019346820869df64694b4dd2556
$ export S3_URL=s3://$bucket/backups/nzoschke/22-07-2012.tgz
$ s3 put --hash
http://mybucket.s3.amazonaws.com/v1/f727790d39db2d05ce6107a0d7783a74892e04b8?AWSAccessKeyId=AKI...&Expires=1343252367&Signature=ji%2BcnJdMgKI3Z1SsWFcR7D2peko%3D
$ s3 get --hash
http://mybucket.s3.amazonaws.com/v1/f727790d39db2d05ce6107a0d7783a74892e04b8?AWSAccessKeyId=AKI...&Expires=1343252414&Signature=7in4wmUeZbjfmQJ5u2SsIe48ZZs%3D
```

The salt version identifier offers a way to rotate keys and update object paths:

```bash
$ S3_PATH_KEY=v2:462aac410b34973b658d9c7fc426a297 s3 put --hash
http://mybucket.s3.amazonaws.com/v2/fb19625bfa0a3f1e1b58a4dff183f90b680fbdfe?AWSAccessKeyId=AKI...&Expires=1343252454&Signature=wUeuASD/0C/oMb6TPu9eUmgNXg8%3D
```
