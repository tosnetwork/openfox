package evolution

import "time"

// NewUnsafeApplierForTest preserves coverage of the legacy rendering and
// rollback mechanics without exporting an activation bypass in production.
func NewUnsafeApplierForTest(paths Paths, now func() time.Time) *Applier {
	applier := NewApplier(paths, now)
	applier.quarantineOnly = false
	return applier
}
