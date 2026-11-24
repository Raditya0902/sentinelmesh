package inspector

import "testing"

func TestScan_PanicResurfacesOnCallerGoroutine(t *testing.T) {
	defer func() {
		if r := recover(); r != "boom" {
			t.Fatalf("expected the job's panic to be re-raised to the caller, got %v", r)
		}
	}()
	ran := false
	scan(func() { ran = true }, func() { panic("boom") })
	t.Fatalf("scan returned normally (ran=%v)", ran)
}
