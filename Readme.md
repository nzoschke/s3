# s3

Generate signed S3 URLs, and GET/PUT S3 objects via cURL

Dependencies: Python 2.7, and curl binary

## Installation

```bash
curl  -o /usr/bin/s3 https://raw.github.com/nzoschke/s3/master/s3.py
chmod +x /usr/bin/s3
```

## Basic Usage

```sh
export S3_ACCESS_KEY_ID=
export S3_SECRET_ACCESS_KEY=

s3 put s3://mybucket/s3.py --file s3.py
s3 get s3://mybucket/s3.py --file s3.py

curl $(s3 get s3://mybucket/s3.py)
```

## Environment

To minimize shell escape problems, and to keep from leaking information to the 
os process table, s3 accepts arguments as environment variables:

```sh
S3_FILE=s3.py S3_URL=s3://mybucket/s3.py s3 put

export S3_URL=s3://mybucket/s3.py
s3 get
s3 put
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

    export S3_PATH_KEY=v1:584ea019346820869df64694b4dd2556
    export S3_URL=s3://mybucket/backups/nzoschke/22-07-2012.tgz
    s3 put --hash
    s3 get --hash

The salt version identifier offers a way to rotate keys and update object paths:

    S3_PATH_KEY=v2:462aac410b34973b658d9c7fc426a297 s3 put --hash
