package abls

import "testing"

func TestBls(t *testing.T) {
	// key generation
	sk, pk, skBytes, pkBytes := KeyGenerate()

	t.Logf("skBytes:\n %v\n", skBytes)
	t.Logf("pkBytes:\n %v\n", pkBytes)

	// signing
	msg := ""
	sig := Sign(sk, msg)
	sigBytes, _ := skBytes.Sign([]byte(msg))

	// transfer

	ook := pkBytes.Verify([]byte(msg), sigBytes)

	// verifying
	ok := Verify(pk, msg, sig)

	if !ok {
		t.Error("verification failed.")
	}
	t.Logf("ook:\n %v\n", ook)
	t.Logf("ok:\n %v\n", ok)
}
func BenchmarkBlsSign(b *testing.B) {
	// key generation
	sk, _, _, _ := KeyGenerate()
	// signing
	msg := "test message"
	for i := 0; i < b.N; i++ {
		Sign(sk, msg)
	}
}

func TestBls2(t *testing.T) {
	// key generation
	sk, pk, skBytes, pkBytes := KeyGenerate()

	t.Logf("skBytes:\n %v\n", skBytes)
	t.Logf("pkBytes:\n %v\n", pkBytes)

	// signing
	msg := "hello world"
	sig := Sign(sk, msg)
	sigBytes, _ := skBytes.Sign([]byte(msg))

	// transfer

	ook := pkBytes.Verify([]byte(msg), sigBytes)

	// verifying
	ok := Verify(pk, msg, sig)

	if !ok {
		t.Error("verification failed.")
	}
	t.Logf("ook:\n %v\n", ook)
	t.Logf("ok:\n %v\n", ok)
}
