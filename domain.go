package hiding

// HidingVerdict of user
type HidingVerdict string

const (
	// HidingVerdictOK user is not hiding
	HidingVerdictOK HidingVerdict = "OK"
	// HidingPartiallyHiding user is partially hiding
	HidingPartiallyHiding HidingVerdict = "PARTIALLY_HIDING"
	// HidingHiding user is hiding
	HidingHiding HidingVerdict = "HIDING"
)

// ComputedHidingRisk is the user hiding risk score
type ComputedHidingRisk struct {
	Verdict                HidingVerdict `json:"v"`
	Token                  string        `json:"t"`
	DenyScore              int           `json:"d"`
	VirtualMachineScore    int           `json:"vm"`
	AntiTrackerScore       int           `json:"a"`
	HideDeviceScore        int           `json:"h"`
	PrivateNavigationScore int           `json:"p"`
	HideRealIPScore        int           `json:"i"`
	BadReputationIPScore   int           `json:"b"`
	RootScore              int           `json:"ro"`
	BotScore               int           `json:"bs"`
}
