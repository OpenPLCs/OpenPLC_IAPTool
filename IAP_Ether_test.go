package main

import "testing"

func TestParsePingStatus(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		chip    string
		mode    string
		version string
	}{
		{name: "valid", input: "STM32H743_BOOT_1.2.3", chip: "STM32H743", mode: "BOOT", version: "1.2.3"},
		{name: "invalid_format", input: "STM32H743,BOOT,1.2.3", wantErr: true},
		{name: "invalid_fields", input: "STM32H743__1.2.3", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePingStatus(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Chip != tt.chip || got.Mode != tt.mode || got.Version != tt.version {
				t.Fatalf("unexpected parse result: %+v", got)
			}
		})
	}
}

func TestParseBoardInfoFromReply(t *testing.T) {
	t.Run("with_mac", func(t *testing.T) {
		got, ok := parseBoardInfoFromReply("STM32H743,CPU123,192.168.1.10,AA:BB:CC:DD:EE:FF", "192.168.1.50")
		if !ok {
			t.Fatalf("expected valid board")
		}
		if got.IP != "192.168.1.10" || got.MAC != "AA:BB:CC:DD:EE:FF" {
			t.Fatalf("unexpected board: %+v", got)
		}
	})

	t.Run("fallback_ip", func(t *testing.T) {
		got, ok := parseBoardInfoFromReply("STM32H743,CPU123,", "192.168.1.50")
		if !ok {
			t.Fatalf("expected valid board with fallback ip")
		}
		if got.IP != "192.168.1.50" {
			t.Fatalf("expected fallback ip, got %s", got.IP)
		}
	})
}

func TestSelectBoardAfterDiscovery(t *testing.T) {
	t.Run("single_board_auto_select", func(t *testing.T) {
		boards := []boardInfo{{IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:01"}}
		got, err := selectBoardAfterDiscovery(boards)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.IP != "192.168.1.10" {
			t.Fatalf("unexpected selected board: %+v", got)
		}
	})

	t.Run("multiple_boards_require_manual_config", func(t *testing.T) {
		boards := []boardInfo{
			{IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:01"},
			{IP: "192.168.1.11", MAC: "AA:BB:CC:DD:EE:02"},
		}
		_, err := selectBoardAfterDiscovery(boards)
		if err == nil {
			t.Fatalf("expected error for multiple boards")
		}
	})
}
