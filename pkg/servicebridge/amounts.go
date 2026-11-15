package servicebridge

import (
	"errors"
	"fmt"
	"math/bits"
	"regexp"
	"strings"
)

// NanoPerTOS is the number of nanoTOS in one TOS.
const NanoPerTOS uint64 = 1_000_000_000

// MaxTOSCTLAmountNano bounds every amount handed to tosctl as decimal TOS.
// tosctl reads such an amount as a 64-bit float and rounds it to nanoTOS;
// below this bound that conversion returns exactly the nanoTOS value that
// was written, so what is previewed is what is signed.
const MaxTOSCTLAmountNano uint64 = 1 << 50

var tosAmountPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,18})(\.[0-9]{1,9})?$`)

// ErrAmountOverflow reports an amount that does not fit nanoTOS arithmetic.
var ErrAmountOverflow = errors.New("servicebridge: the amount overflows nanoTOS arithmetic")

// ParseTOSAmount reads a plain decimal TOS amount (no sign, no exponent, at
// most nine fractional digits) into nanoTOS with checked arithmetic.
func ParseTOSAmount(text string) (uint64, error) {
	if !tosAmountPattern.MatchString(text) {
		return 0, fmt.Errorf("servicebridge: %q is not a decimal TOS amount with at most 9 fractional digits", text)
	}
	whole, fraction, _ := strings.Cut(text, ".")
	var units uint64
	for _, digit := range whole {
		next, err := checkedMul(units, 10)
		if err != nil {
			return 0, err
		}
		if units, err = checkedAdd(next, uint64(digit-'0')); err != nil {
			return 0, err
		}
	}
	var nano uint64
	for index := 0; index < 9; index++ {
		nano *= 10
		if index < len(fraction) {
			nano += uint64(fraction[index] - '0')
		}
	}
	scaled, err := checkedMul(units, NanoPerTOS)
	if err != nil {
		return 0, err
	}
	return checkedAdd(scaled, nano)
}

// FormatTOSAmount renders nanoTOS as decimal TOS with all nine fractional
// digits, the exact form handed to tosctl.
func FormatTOSAmount(nano uint64) string {
	return fmt.Sprintf("%d.%09d", nano/NanoPerTOS, nano%NanoPerTOS)
}

func checkedAdd(a, b uint64) (uint64, error) {
	sum, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return 0, ErrAmountOverflow
	}
	return sum, nil
}

func checkedSub(a, b uint64) (uint64, error) {
	if b > a {
		return 0, ErrAmountOverflow
	}
	return a - b, nil
}

func checkedMul(a, b uint64) (uint64, error) {
	high, low := bits.Mul64(a, b)
	if high != 0 {
		return 0, ErrAmountOverflow
	}
	return low, nil
}

// tosctlAmount renders an amount for a tosctl flag, refusing zero where the
// caller requires a positive amount and anything above the exact bound.
func tosctlAmount(nano uint64, name string, allowZero bool) (string, error) {
	if nano == 0 && !allowZero {
		return "", fmt.Errorf("servicebridge: %s must be greater than zero", name)
	}
	if nano > MaxTOSCTLAmountNano {
		return "", fmt.Errorf("servicebridge: %s exceeds %s TOS, the largest amount tosctl takes exactly", name,
			FormatTOSAmount(MaxTOSCTLAmountNano))
	}
	return FormatTOSAmount(nano), nil
}
