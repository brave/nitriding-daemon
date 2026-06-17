package main

import (
	"os"
	"testing"
)

func TestWriteResolvconf(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "nameserver only",
			cfg:  Config{},
			want: "nameserver " + defaultGw + "\n",
		},
		{
			name: "with search",
			cfg:  Config{ResolvSearch: "foo.internal bar.internal"},
			want: "nameserver " + defaultGw + "\n" +
				"search foo.internal bar.internal\n",
		},
		{
			name: "with ndots",
			cfg:  Config{ResolvNdots: 2},
			want: "nameserver " + defaultGw + "\n" +
				"options ndots:2\n",
		},
		{
			name: "with search and ndots",
			cfg: Config{
				ResolvSearch: "foo.internal",
				ResolvNdots:  5,
			},
			want: "nameserver " + defaultGw + "\n" +
				"search foo.internal\n" +
				"options ndots:5\n",
		},
	}

	origDir := resolvconfDir
	t.Cleanup(func() { resolvconfDir = origDir })

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolvconfDir = t.TempDir() + "/"

			if err := writeResolvconf(&tc.cfg); err != nil {
				t.Fatalf("writeResolvconf: %v", err)
			}

			got, err := os.ReadFile(resolvconfDir + "resolv.conf")
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("got:\n%q\nwant:\n%q", got, tc.want)
			}
		})
	}
}
