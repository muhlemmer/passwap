package testvalues

import "bytes"

const (
	RoundsSHA2    uint32 = 10000
	EncodedSHA256        = `$5$rounds=10000$randomsaltishard$/gvdY2rW3WNeR4vDx0xMNYULV.FjQ2tJPv0u5senhU9`
	EncodedSHA512        = `$6$rounds=10000$randomsaltishard$CbTMkwycAkbz9nsD6C9K6ZdJjifBMfRrYtxzcZxMg.WRBAcfpj/FSsofuPDyjHxPRG.sKy8.IJk5xC3kFTSQi.`
)

var (
	ChecksumSHA256 = bytes.Split([]byte(EncodedSHA256), []byte("$"))[4]
	ChecksumSHA512 = bytes.Split([]byte(EncodedSHA512), []byte("$"))[4]
)
