package enc_uuid_test

import (
	"../golang-encrypted-uuid"
	"fmt"
	"log"
	"testing"
)

func TestGenerate(t *testing.T) {
	// Generator
	generator := enc_uuid.New([]byte("mysecret90123456"), true)

	// Encrypt
	enc, err := generator.Encrypt([]byte("test"))
	if err != nil {
		panic(err)
	}
	log.Printf("%s", enc)

	// Decrypt
	dec, err := generator.Decrypt(enc)
	if err != nil {
		panic(err)
	}
	log.Printf("%v %s", dec, string(dec))

	// Generate
	u := generator.New()
	log.Println(u)
	log.Println(u.UuidStr(generator))
	log.Println(u.ToString())

	// Parse
	parsed, e := generator.Parse("T5LvxuSpeC0g2VglOnOACOzuFP0wmH04l49fQmSWR5+kpIXvGXzO0g==")
	if e != nil {
		panic(e)
	}
	parsedStr, _ := parsed.UuidStr(generator)
	if parsedStr != "0c53cb40-fe28-4051-7c8f-318a1a870ee4" {
		panic(fmt.Sprintf("Failed read got ", parsedStr))
	}
	parsedStrCached, _ := parsed.UuidStr(generator)
	if parsedStrCached != "0c53cb40-fe28-4051-7c8f-318a1a870ee4" {
		panic("Failed read cache")
	}

	// Additional data
	ud := generator.NewWithAdditionalData("c=1")
	log.Printf("Encrypted with data %s", ud)
	log.Println(ud.UuidStr(generator))
	data, _ := ud.AdditionalDataStr(generator)
	if data != "c=1" {
		panic("Failed additional data read")
	}

	// Test data modification
	setE := ud.SetAdditionalData(generator, "c=2")
	if setE != nil {
		panic(fmt.Sprintf("Failed to set data: %s", setE))
	}
	log.Printf("Encrypted with data changed %s", ud)
	log.Println(ud.UuidStr(generator))
	data2, _ := ud.AdditionalDataStr(generator)
	if data2 != "c=2" {
		panic("Failed additional data read after change")
	}

	// Read something non-encrypted
	unecryptedU, eUnecrypted := generator.Parse("0c53cb40-fe28-4051-7c8f-318a1a870ee5")
	log.Println(eUnecrypted)
	log.Println(unecryptedU)
	parsedUnecryptedStr, _ := unecryptedU.UuidStr(generator)
	if parsedUnecryptedStr != "0c53cb40-fe28-4051-7c8f-318a1a870ee5" {
		panic("Failed read unencrypted")
	}

	// Read something bullshit non-encrypted
	unecryptedUbs, eUnecryptedBs := generator.Parse("123")
	if eUnecryptedBs == nil || unecryptedUbs != nil {
		panic("Should not be able to read bullshit in grace mode")
	}

	// Read non-encrypted without grace mode
	nonGracefulGenerator := enc_uuid.New([]byte("mysecret90123456"), false)
	unecryptedUnonGrace, eUnecryptedNonGrace := nonGracefulGenerator.Parse("0c53cb40-fe28-4051-7c8f-318a1a870ee5")
	if eUnecryptedNonGrace == nil || unecryptedUnonGrace != nil {
		panic("Should not be able to read non-encrypted in non-grace mode")
	}

	// Read something bullshit non-encrypted non grace
	unecryptedUbsNnonGrace, eUnecryptedBsNonGrace := generator.Parse("123")
	if unecryptedUbsNnonGrace != nil || eUnecryptedBsNonGrace == nil {
		panic("Should not be able to read bullshit in non-grace mode")
	}
}
