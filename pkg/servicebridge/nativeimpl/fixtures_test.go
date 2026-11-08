package nativeimpl

import "strings"

const hex64 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func repeatHex(pair string) string { return strings.Repeat(pair, 32) }
