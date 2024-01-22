package hiding

type Reader interface {
	Read(msg string) (*ComputedHidingRisk, error)
}
