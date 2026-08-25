package platformexec

import "testing"

func TestCappedBufferBoundsMemoryWithoutBlockingChildWrites(t *testing.T) {
	buffer := &cappedBuffer{maximum: 5}
	if written, err := buffer.Write([]byte("123")); err != nil || written != 3 {
		t.Fatalf("first Write() = %d, %v", written, err)
	}
	if written, err := buffer.Write([]byte("456789")); err != nil || written != 6 {
		t.Fatalf("second Write() = %d, %v", written, err)
	}
	if buffer.String() != "12345" || !buffer.exceeded {
		t.Fatalf("capped buffer = %q exceeded=%v", buffer.String(), buffer.exceeded)
	}
	unlimited := &cappedBuffer{}
	_, _ = unlimited.Write([]byte("unbounded"))
	if unlimited.String() != "unbounded" || unlimited.exceeded {
		t.Fatalf("unlimited buffer = %q exceeded=%v", unlimited.String(), unlimited.exceeded)
	}
}
