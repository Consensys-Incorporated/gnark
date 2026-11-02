package profile

import "testing"

func TestIsAnonymousFunc(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{name: "pkg.Func.func1", want: true},
		{name: "pkg.Func.func2", want: true},
		{name: "pkg.Func.func10", want: true},
		{name: "pkg.Func.func2.1", want: true},
		{name: "pkg.Func", want: false},
		{name: "pkg.Function1", want: false},
		{name: "pkg.Func.funcx", want: false},
		{name: "pkg.Func.func1.extra", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAnonymousFunc(tc.name); got != tc.want {
				t.Errorf("isAnonymousFunc(%q) = %t, want %t", tc.name, got, tc.want)
			}
		})
	}
}
