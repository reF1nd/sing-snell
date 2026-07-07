package test

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-snell/internal/multiuser"
)

func newAuthenticator(userCount int) *multiuser.Authenticator {
	credentials := make([][]byte, userCount)
	for index := range credentials {
		credentials[index] = []byte{byte(index >> 8), byte(index)}
	}
	return multiuser.New(credentials)
}

func authenticateUser(authenticator *multiuser.Authenticator, user int) error {
	_, index, err := authenticator.Authenticate(func(candidate []byte) bool {
		return int(candidate[0])<<8|int(candidate[1]) == user
	})
	if err == nil && index != user {
		return fmt.Errorf("matched user %d, want %d", index, user)
	}
	return err
}

func trainAuthenticator() *multiuser.Authenticator {
	authenticator := newAuthenticator(12)
	for user, hits := range []int{50, 30, 10, 10} {
		for range hits {
			if err := authenticateUser(authenticator, user); err != nil {
				panic(err)
			}
		}
	}
	return authenticator
}

func TestAuthenticatorCoversColdUsers(t *testing.T) {
	authenticator := newAuthenticator(32)
	for range 128 {
		if err := authenticateUser(authenticator, 3); err != nil {
			t.Fatal(err)
		}
	}
	if err := authenticateUser(authenticator, 31); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticatorRejectsUnknownCredential(t *testing.T) {
	authenticator := newAuthenticator(2)
	_, _, err := authenticator.Authenticate(func([]byte) bool { return false })
	if err == nil {
		t.Fatal("expected authentication failure")
	}
}

func TestAuthenticatorReturnsMatchResult(t *testing.T) {
	authenticator := newAuthenticator(12)
	credential, index, result, err := multiuser.AuthenticateWithResult(authenticator, func(candidate []byte) (string, bool) {
		user := int(candidate[0])<<8 | int(candidate[1])
		return fmt.Sprintf("user-%d", user), user == 7
	})
	if err != nil {
		t.Fatal(err)
	}
	if index != 7 || result != "user-7" || credential[1] != 7 {
		t.Fatalf("unexpected match: index=%d result=%q credential=%v", index, result, credential)
	}
}

func TestAuthenticatorSelectsAdaptiveHotPrefix(t *testing.T) {
	for user, expectedAttempts := range map[int]int{0: 1, 1: 2, 2: 3} {
		authenticator := trainAuthenticator()
		attempts := 0
		_, index, err := authenticator.Authenticate(func(candidate []byte) bool {
			attempts++
			return int(candidate[0])<<8|int(candidate[1]) == user
		})
		if err != nil {
			t.Fatal(err)
		}
		if index != user || attempts != expectedAttempts {
			t.Fatalf("user %d matched after %d attempts, want %d", user, attempts, expectedAttempts)
		}
	}
}

func TestAuthenticatorPopularityDecays(t *testing.T) {
	authenticator := newAuthenticator(2)
	for range 1024 {
		if err := authenticateUser(authenticator, 0); err != nil {
			t.Fatal(err)
		}
	}
	for range 1024 {
		if err := authenticateUser(authenticator, 1); err != nil {
			t.Fatal(err)
		}
	}
	attempts := 0
	_, _, err := authenticator.Authenticate(func(candidate []byte) bool {
		attempts++
		return candidate[1] == 1
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 1 {
		t.Fatalf("recent user matched after %d attempts, want 1", attempts)
	}
}

func TestAuthenticatorConcurrentAccounting(t *testing.T) {
	authenticator := newAuthenticator(12)
	var group sync.WaitGroup
	for range 64 {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := authenticateUser(authenticator, 7); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	attempts := 0
	_, _, err := authenticator.Authenticate(func(candidate []byte) bool {
		attempts++
		return candidate[1] == 7
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 1 {
		t.Fatalf("popular user matched after %d attempts, want 1", attempts)
	}
}

func TestAuthenticatorBoundsParallelWorkers(t *testing.T) {
	const userCount = 64
	authenticator := newAuthenticator(userCount)
	started := make(chan struct{}, 2*userCount)
	release := make(chan struct{})
	var active atomic.Int32
	done := make(chan error, 2)
	authenticate := func() {
		_, _, err := authenticator.Authenticate(func([]byte) bool {
			active.Add(1)
			started <- struct{}{}
			<-release
			active.Add(-1)
			return false
		})
		done <- err
	}
	go authenticate()
	for range multiuser.MaxParallelWorkers {
		<-started
	}
	go authenticate()
	<-started
	if current := active.Load(); current != int32(multiuser.MaxParallelWorkers+1) {
		t.Fatalf("active workers %d, want %d", current, multiuser.MaxParallelWorkers+1)
	}
	close(release)
	for range 2 {
		if err := <-done; err == nil {
			t.Fatal("expected authentication failure")
		}
	}
}

func TestAuthenticatorHotPathDoesNotAllocate(t *testing.T) {
	t.Run("boolean", func(t *testing.T) {
		authenticator := newAuthenticator(12)
		match := func(candidate []byte) bool { return candidate[1] == 3 }
		for range 128 {
			if _, _, err := authenticator.Authenticate(match); err != nil {
				t.Fatal(err)
			}
		}
		allocations := testing.AllocsPerRun(1000, func() {
			if _, _, err := authenticator.Authenticate(match); err != nil {
				panic(err)
			}
		})
		if allocations != 0 {
			t.Fatalf("hot authentication allocations = %v, want 0", allocations)
		}
	})
	t.Run("result", func(t *testing.T) {
		authenticator := newAuthenticator(12)
		match := func(candidate []byte) (struct{}, bool) { return struct{}{}, candidate[1] == 3 }
		for range 128 {
			if _, _, _, err := multiuser.AuthenticateWithResult(authenticator, match); err != nil {
				t.Fatal(err)
			}
		}
		allocations := testing.AllocsPerRun(1000, func() {
			if _, _, _, err := multiuser.AuthenticateWithResult(authenticator, match); err != nil {
				panic(err)
			}
		})
		if allocations != 0 {
			t.Fatalf("hot authentication allocations = %v, want 0", allocations)
		}
	})
}

func TestAuthenticatorSerialColdPathDoesNotAllocate(t *testing.T) {
	authenticator := newAuthenticator(4096)
	started := make(chan struct{}, multiuser.MaxParallelWorkers)
	release := make(chan struct{})
	done := make(chan error, 1)
	var startedCount atomic.Int32
	go func() {
		_, _, err := authenticator.Authenticate(func([]byte) bool {
			if startedCount.Add(1) <= multiuser.MaxParallelWorkers {
				started <- struct{}{}
				<-release
			}
			return false
		})
		done <- err
	}()
	for range multiuser.MaxParallelWorkers {
		<-started
	}

	match := func([]byte) bool { return false }
	allocations := testing.AllocsPerRun(100, func() {
		if _, _, err := authenticator.Authenticate(match); err == nil {
			panic("expected authentication failure")
		}
	})
	close(release)
	if err := <-done; err == nil {
		t.Fatal("expected authentication failure")
	}
	if allocations != 0 {
		t.Fatalf("serial cold authentication allocations = %v, want 0", allocations)
	}
}

func BenchmarkAuthenticatorHotPath(b *testing.B) {
	for _, userCount := range []int{8, 64, 4096} {
		b.Run(fmt.Sprintf("users_%d", userCount), func(b *testing.B) {
			authenticator := newAuthenticator(userCount)
			match := func(candidate []byte) (struct{}, bool) { return struct{}{}, candidate[1] == 0 }
			for range 128 {
				_, _, _, _ = multiuser.AuthenticateWithResult(authenticator, match)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_, _, _, _ = multiuser.AuthenticateWithResult(authenticator, match)
			}
		})
	}
}

func BenchmarkAuthenticatorColdPath(b *testing.B) {
	for _, userCount := range []int{64, 4096} {
		b.Run(fmt.Sprintf("users_%d", userCount), func(b *testing.B) {
			authenticator := newAuthenticator(userCount)
			match := func([]byte) bool { return false }
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_, _, _ = authenticator.Authenticate(match)
			}
		})
	}
}
