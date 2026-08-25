package networkplan

import "testing"

func TestBuildCreatesIsolatedRoutesForEveryModem(t *testing.T) {
	plan, err := Build(Input{
		LANPrefix:       "192.168.200.0/24",
		WireGuardPrefix: "10.80.0.0/24",
		Modems: []ModemInput{
			{ID: "modem-b", Priority: 20, InterfaceName: "enx0002", ManagementPrefix: "192.168.9.0/24", Gateway: "192.168.9.1", RoutingTableID: 1102, Fwmark: 0x1102},
			{ID: "modem-a", Priority: 10, InterfaceName: "enx0001", ManagementPrefix: "192.168.8.0/24", Gateway: "192.168.8.1", RoutingTableID: 1101, Fwmark: 0x1101},
		},
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if plan.Owner != Owner || len(plan.Routes) != 4 || len(plan.Rules) != 2 {
		t.Fatalf("plan = %+v", plan)
	}
	if plan.Rules[0].ModemID != "modem-a" || plan.Rules[0].TableID != 1101 || plan.Rules[0].Fwmark != 0x1101 {
		t.Fatalf("first rule = %+v", plan.Rules[0])
	}
	for _, route := range plan.Routes {
		if route.TableID == 254 || route.TableID < 256 {
			t.Fatalf("route leaked into reserved/main table: %+v", route)
		}
	}
}

func TestBuildRejectsSubnetAndRoutingConflicts(t *testing.T) {
	base := Input{
		LANPrefix:       "192.168.200.0/24",
		WireGuardPrefix: "10.80.0.0/24",
		Modems: []ModemInput{
			{ID: "modem-a", Priority: 10, InterfaceName: "enx0001", ManagementPrefix: "192.168.8.0/24", Gateway: "192.168.8.1", RoutingTableID: 1101, Fwmark: 0x1101},
			{ID: "modem-b", Priority: 20, InterfaceName: "enx0002", ManagementPrefix: "192.168.9.0/24", Gateway: "192.168.9.1", RoutingTableID: 1102, Fwmark: 0x1102},
		},
	}
	tests := []struct {
		name   string
		mutate func(*Input)
	}{
		{"overlapping modem subnets", func(input *Input) { input.Modems[1].ManagementPrefix = "192.168.8.128/25" }},
		{"LAN overlap", func(input *Input) {
			input.Modems[1].ManagementPrefix = "192.168.200.0/25"
			input.Modems[1].Gateway = "192.168.200.1"
		}},
		{"duplicate table", func(input *Input) { input.Modems[1].RoutingTableID = 1101 }},
		{"duplicate mark", func(input *Input) { input.Modems[1].Fwmark = 0x1101 }},
		{"duplicate interface", func(input *Input) { input.Modems[1].InterfaceName = "enx0001" }},
		{"gateway outside subnet", func(input *Input) { input.Modems[1].Gateway = "192.168.10.1" }},
		{"reserved table", func(input *Input) { input.Modems[1].RoutingTableID = 254 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base
			input.Modems = append([]ModemInput(nil), base.Modems...)
			test.mutate(&input)
			if _, err := Build(input); err == nil {
				t.Fatal("Build() error = nil, want conflict")
			}
		})
	}
}
