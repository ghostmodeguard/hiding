package ghostmodeguard

var _ Reader = &ReaderSpy{}

// ReaderSpy is a reader spy
type ReaderSpy struct {
	recordedMsg *string
	called      bool
	risk        *ComputedHidingRisk
	err         error
}

// NewReaderSpy creates a spy instance of Reader
func NewReaderSpy(risk *ComputedHidingRisk, err error) *ReaderSpy {
	return &ReaderSpy{
		risk: risk,
		err:  err,
	}
}

// Read implements Reader
func (r *ReaderSpy) Read(msg string) (*ComputedHidingRisk, error) {
	r.recordedMsg = &msg
	r.called = true
	return r.risk, r.err
}

// GetRecordedMsg returns message recorded on Read
func (r *ReaderSpy) GetRecordedMsg() *string {
	return r.recordedMsg
}

// HasBeenRead returns if Read method has been called
func (r *ReaderSpy) HasBeenRead() bool {
	return r.called
}
