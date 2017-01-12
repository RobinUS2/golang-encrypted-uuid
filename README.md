# golang-encrypted-uuid [![Build status](https://api.travis-ci.org/RobinUS2/presto-bloomfilter.svg)](https://travis-ci.org/RobinUS2/golang-encrypted-uuid)
Encrypt a UUID (common use case as tracking cookie)

## Example: creating
```
generator := enc_uuid.New([]byte("mysecret90123456"), true)
u := generator.New()
log.Println(u.ToString()) // Encrypted string
```

## Example: reading
```
generator := enc_uuid.New([]byte("mysecret90123456"), true)
parsed, _ := generator.Parse("T5LvxuSpeC0g2VglOnOACOzuFP0wmH04l49fQmSWR5+kpIXvGXzO0g==")
parsedStr, _ := parsed.UuidStr(generator)
log.Println(parsedStr) // Decrypted hex string representation of the uuid v4
```