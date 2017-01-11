package enc_uuid_test

import (
	"../golang-encrypted-uuid"
	"github.com/nu7hatch/gouuid"
	"testing"
)

const KEY_AES_128 string = "mysecret90123456"
const KEY_AES_192 string = "mysecret9012345612345678"
const KEY_AES_256 string = "mysecret901234561234567812345678"

// Without encryption creation
func BenchmarkCreatePlain(b *testing.B) {
	for n := 0; n < b.N; n++ {
		u, _ := uuid.NewV4()
		u.String()
	}
}

// Without encryption reading
func BenchmarkReadPlain(b *testing.B) {
	str := "123fa63d-2afd-4234-4e31-26af1f24d0f5"
	for n := 0; n < b.N; n++ {
		uuid, _ := uuid.ParseHex(str)
		uuid.String()
	}
}

// Without encryption reading
func BenchmarkCreateReadPlain(b *testing.B) {
	for n := 0; n < b.N; n++ {
		u, _ := uuid.NewV4()
		str := u.String()
		uuid, _ := uuid.ParseHex(str)
		uuid.String()
	}
}

func BenchmarkCreateAes128(b *testing.B) {
	generator := enc_uuid.New([]byte(KEY_AES_128), true)
	doWrite(b, generator)
}

func BenchmarkReadAes128(b *testing.B) {
	generator := enc_uuid.New([]byte(KEY_AES_128), true)
	doRead(b, generator)
}

func BenchmarkReadGraceAes128(b *testing.B) {
	generator := enc_uuid.New([]byte(KEY_AES_128), true)
	doReadGraceful(b, generator)
}

func BenchmarkCreateReadAes128(b *testing.B) {
	generator := enc_uuid.New([]byte(KEY_AES_128), true)
	doWriteThenRead(b, generator)
}

func BenchmarkCreateAes192(b *testing.B) {
	generator := enc_uuid.New([]byte(KEY_AES_192), true)
	doWrite(b, generator)
}

func BenchmarkReadAes192(b *testing.B) {
	generator := enc_uuid.New([]byte(KEY_AES_192), true)
	doRead(b, generator)
}

func BenchmarkReadGraceAes192(b *testing.B) {
	generator := enc_uuid.New([]byte(KEY_AES_192), true)
	doReadGraceful(b, generator)
}

func BenchmarkCreateReadAes192(b *testing.B) {
	generator := enc_uuid.New([]byte(KEY_AES_192), true)
	doWriteThenRead(b, generator)
}

func BenchmarkCreateAes256(b *testing.B) {
	generator := enc_uuid.New([]byte(KEY_AES_256), true)
	doWrite(b, generator)
}

func BenchmarkReadAes256(b *testing.B) {
	generator := enc_uuid.New([]byte(KEY_AES_256), true)
	doRead(b, generator)
}

func BenchmarkReadGraceAes256(b *testing.B) {
	generator := enc_uuid.New([]byte(KEY_AES_256), true)
	doReadGraceful(b, generator)
}

func BenchmarkCreateReadAes256(b *testing.B) {
	generator := enc_uuid.New([]byte(KEY_AES_256), true)
	doWriteThenRead(b, generator)
}

func doWriteThenRead(b *testing.B, generator *enc_uuid.EncUuidGenerator) {
	for n := 0; n < b.N; n++ {
		u := generator.New()
		str := u.ToString()
		parsed, e := generator.Parse(str)
		if e != nil {
			panic("Failed parse")
		}
		_, e2 := parsed.UuidStr(generator)
		if e2 != nil {
			panic("Failed to uuid")
		}
	}
}

func doWrite(b *testing.B, generator *enc_uuid.EncUuidGenerator) {
	for n := 0; n < b.N; n++ {
		u := generator.New()
		u.ToString()
	}
}

func doRead(b *testing.B, generator *enc_uuid.EncUuidGenerator) {
	u := generator.New()
	str := u.ToString()
	for n := 0; n < b.N; n++ {
		parsed, e := generator.Parse(str)
		if e != nil {
			panic("Failed parse")
		}
		parsed.UuidStr(generator)
	}
}

func doReadGraceful(b *testing.B, generator *enc_uuid.EncUuidGenerator) {
	str := "123fa63d-2afd-4234-4e31-26af1f24d0f5"
	for n := 0; n < b.N; n++ {
		parsed, e := generator.Parse(str)
		if e != nil {
			panic("Failed parse")
		}
		parsed.UuidStr(generator)
	}
}
