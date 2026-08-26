//go:build !linux

package earning

import (
	"context"
	"errors"
)

func (sink *TOSCTLPaymentSink) pinTOSCTLExecutable() error {
	return errors.New("descriptor-pinned tosctl custody is supported only on Linux")
}

func (sink *TOSCTLPaymentSink) runPinnedTOSCTL(context.Context, []string, []string) ([]byte, error) {
	return nil, errors.New("descriptor-pinned tosctl custody is supported only on Linux")
}
