package hiding

// ComputedHidingRisk is the user hiding risk score
type ComputedHidingRisk struct {
	Token                  string `json:"t"`
	DenyScore              int    `json:"d"`
	VirtualMachineScore    int    `json:"vm"`
	AntiTrackerScore       int    `json:"a"`
	HideDeviceScore        int    `json:"h"`
	PrivateNavigationScore int    `json:"p"`
	HideRealIPScore        int    `json:"i"`
	BadReputationIPScore   int    `json:"b"`
	RootScore              int    `json:"ro"`
	BotScore               int    `json:"bs"`
}
