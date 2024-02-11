package hiding

// Verdict of user
type Verdict string

const (
	// VerdictOK user is not hiding
	VerdictOK Verdict = "OK"
	// PartiallyHiding user
	PartiallyHiding Verdict = "PARTIALLY_HIDING"
	// Hiding user
	Hiding Verdict = "HIDING"
)

// ComputedHidingRisk is the user hiding risk score
type ComputedHidingRisk struct {
	Verdict                Verdict `json:"v"`
	Token                  string  `json:"t"`
	DenyScore              int     `json:"d"`
	VirtualMachineScore    int     `json:"vm"`
	AntiTrackerScore       int     `json:"a"`
	HideDeviceScore        int     `json:"h"`
	PrivateNavigationScore int     `json:"p"`
	HideRealIPScore        int     `json:"i"`
	BadReputationIPScore   int     `json:"b"`
	RootScore              int     `json:"ro"`
	BotScore               int     `json:"bs"`
}
