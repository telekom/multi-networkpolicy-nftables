package server

import (
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

func TestOptionsValidateRequiresContainerRuntimeEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		endpoint string
	}{
		{name: "empty"},
		{name: "whitespace", endpoint: " \t "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := NewOptions()
			opts.containerRuntimeEndpoint = tt.endpoint

			if err := opts.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want endpoint error")
			}
		})
	}
}

func TestOptionsValidateRequiresContainerRuntimeEndpointPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		endpoint string
	}{
		{name: "relative path", endpoint: "run/crio/crio.sock"},
		{name: "unix URL", endpoint: "unix:///run/crio/crio.sock"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := NewOptions()
			opts.containerRuntimeEndpoint = tt.endpoint

			if err := opts.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want endpoint path error")
			}
		})
	}
}

func TestOptionsValidateTrimsContainerRuntimeEndpoint(t *testing.T) {
	t.Parallel()

	opts := NewOptions()
	opts.containerRuntimeEndpoint = " /run/crio/crio.sock "

	if err := opts.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if opts.containerRuntimeEndpoint != "/run/crio/crio.sock" {
		t.Fatalf("containerRuntimeEndpoint = %q, want trimmed path", opts.containerRuntimeEndpoint)
	}
}

func TestOptionsValidateParsesCIDRPrefixes(t *testing.T) {
	t.Parallel()

	opts := NewOptions()
	opts.containerRuntimeEndpoint = "/run/crio/crio.sock"
	opts.allowSrcPrefixText = " fe80::/10 , 10.0.0.0/24 "
	opts.allowDstPrefixText = "ff00::/8"

	if err := opts.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if want := []string{"fe80::/10", "10.0.0.0/24"}; !reflect.DeepEqual(opts.allowSrcPrefix, want) {
		t.Fatalf("allowSrcPrefix = %#v, want %#v", opts.allowSrcPrefix, want)
	}
	if want := []string{"ff00::/8"}; !reflect.DeepEqual(opts.allowDstPrefix, want) {
		t.Fatalf("allowDstPrefix = %#v, want %#v", opts.allowDstPrefix, want)
	}
}

func TestOptionsValidateRejectsInvalidCIDRPrefix(t *testing.T) {
	t.Parallel()

	opts := NewOptions()
	opts.containerRuntimeEndpoint = "/run/crio/crio.sock"
	opts.allowSrcPrefixText = "not-a-cidr"

	if err := opts.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want CIDR parse error")
	}
}

func TestBuildReconcilerConfigCarriesOptions(t *testing.T) {
	t.Parallel()

	opts := NewOptions()
	opts.Kubeconfig = "/tmp/kubeconfig"
	opts.master = "https://api.example.test"
	opts.hostnameOverride = "node-a"
	opts.hostPrefix = "/host"
	opts.containerRuntimeEndpoint = "/run/crio/crio.sock"
	opts.networkPlugins = []string{"macvlan", "ipvlan"}
	opts.syncPeriod = 7
	opts.acceptICMP = true
	opts.allowDstPrefixText = "ff00::/8"

	cfg, err := opts.BuildReconcilerConfig()
	if err != nil {
		t.Fatalf("BuildReconcilerConfig() error = %v", err)
	}
	if cfg.Kubeconfig != opts.Kubeconfig {
		t.Fatalf("Kubeconfig = %q, want %q", cfg.Kubeconfig, opts.Kubeconfig)
	}
	if cfg.Master != opts.master {
		t.Fatalf("Master = %q, want %q", cfg.Master, opts.master)
	}
	if cfg.NodeName != opts.hostnameOverride {
		t.Fatalf("NodeName = %q, want %q", cfg.NodeName, opts.hostnameOverride)
	}
	if cfg.HostPrefix != opts.hostPrefix {
		t.Fatalf("HostPrefix = %q, want %q", cfg.HostPrefix, opts.hostPrefix)
	}
	if cfg.ContainerRuntimeEndpoint != opts.containerRuntimeEndpoint {
		t.Fatalf("ContainerRuntimeEndpoint = %q, want %q", cfg.ContainerRuntimeEndpoint, opts.containerRuntimeEndpoint)
	}
	if !reflect.DeepEqual(cfg.NetworkPlugins, opts.networkPlugins) {
		t.Fatalf("NetworkPlugins = %#v, want %#v", cfg.NetworkPlugins, opts.networkPlugins)
	}
	if cfg.SyncPeriodSeconds != opts.syncPeriod {
		t.Fatalf("SyncPeriodSeconds = %d, want %d", cfg.SyncPeriodSeconds, opts.syncPeriod)
	}
	if !cfg.CommonRuleConfig.AcceptICMP {
		t.Fatal("CommonRuleConfig.AcceptICMP = false, want true")
	}
	if want := []string{"ff00::/8"}; !reflect.DeepEqual(cfg.CommonRuleConfig.AllowDstPrefix, want) {
		t.Fatalf("AllowDstPrefix = %#v, want %#v", cfg.CommonRuleConfig.AllowDstPrefix, want)
	}
	// The SR-IOV tc backend is opt-in.
	if cfg.EnableTCBackend {
		t.Fatal("EnableTCBackend = true, want false (opt-in)")
	}
}

func TestTCBackendIsOptIn(t *testing.T) {
	t.Parallel()

	if NewOptions().enableTCBackend {
		t.Fatal("NewOptions default enableTCBackend = true, want false (opt-in)")
	}

	// Enabling it is carried through BuildReconcilerConfig. (The flag wiring
	// and its false default are verified in
	// TestAddFlagsAcceptsDeprecatedIptablesStateFlagNoop, which owns the single
	// AddFlags call: klog.InitFlags panics if AddFlags runs twice per binary.)
	on := NewOptions()
	on.enableTCBackend = true
	on.containerRuntimeEndpoint = "/run/crio/crio.sock"
	on.hostnameOverride = "n"
	cfg, err := on.BuildReconcilerConfig()
	if err != nil {
		t.Fatalf("BuildReconcilerConfig: %v", err)
	}
	if !cfg.EnableTCBackend {
		t.Fatal("cfg.EnableTCBackend = false, want true after enabling")
	}
}

func TestAddFlagsAcceptsDeprecatedIptablesStateFlagNoop(t *testing.T) {
	opts := NewOptions()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	opts.AddFlags(fs)

	// The SR-IOV tc backend flag is opt-in: registered with a false default.
	if tcFlag := fs.Lookup("enable-tc-backend"); tcFlag == nil {
		t.Fatal("enable-tc-backend flag was not registered")
	} else if tcFlag.DefValue != "false" {
		t.Fatalf("--enable-tc-backend default = %q, want \"false\"", tcFlag.DefValue)
	}
	for name, want := range map[string]string{"tc-default-deny": "none", "tc-cleanup-on-start": "false"} {
		if f := fs.Lookup(name); f == nil || f.DefValue != want {
			t.Fatalf("--%s default = %+v, want %q", name, f, want)
		}
	}

	if err := fs.Parse([]string{
		"--pod-iptables=/tmp/old-state",
		"--container-runtime-endpoint=/run/crio/crio.sock",
		"--enable-tc-backend",
	}); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !opts.enableTCBackend {
		t.Fatal("--enable-tc-backend did not enable the backend")
	}

	flag := fs.Lookup("pod-iptables")
	if flag == nil {
		t.Fatal("deprecated pod-iptables flag was not registered")
	}
	if !flag.Hidden {
		t.Fatal("deprecated pod-iptables flag is not hidden")
	}
	if flag.Deprecated == "" {
		t.Fatal("deprecated pod-iptables flag has no deprecation message")
	}

	if _, err := opts.BuildReconcilerConfig(); err != nil {
		t.Fatalf("BuildReconcilerConfig() error = %v", err)
	}
}

// TestTCDefaultDenyFlag: --tc-default-deny takes the same values as a
// default-deny flag of any backend, maps them to directions, and is only
// accepted together with --enable-tc-backend.
func TestTCDefaultDenyFlag(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		value           string
		enabled         bool
		ingress, egress bool
		wantErr         string
	}{
		{value: "", enabled: false},
		{value: "none", enabled: false},
		{value: "none", enabled: true},
		{value: "ingress", enabled: true, ingress: true},
		{value: "egress", enabled: true, egress: true},
		{value: "all", enabled: true, ingress: true, egress: true},
		{value: "both", enabled: true, wantErr: `tc-default-deny "both" is invalid, must be one of none, ingress, egress or all`},
		{value: "all", enabled: false, wantErr: "needs --enable-tc-backend"},
		{value: "ingress", enabled: false, wantErr: "needs --enable-tc-backend"},
	} {
		o := NewOptions()
		o.containerRuntimeEndpoint = "/run/crio/crio.sock"
		o.hostnameOverride = "n"
		o.tcDefaultDeny = tt.value
		o.enableTCBackend = tt.enabled
		cfg, err := o.BuildReconcilerConfig()
		if tt.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("value %q, enabled %v: err = %v, want it to contain %q", tt.value, tt.enabled, err, tt.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("value %q, enabled %v: unexpected error %v", tt.value, tt.enabled, err)
			continue
		}
		if cfg.CommonRuleConfig.TCDefaultDenyIngress != tt.ingress || cfg.CommonRuleConfig.TCDefaultDenyEgress != tt.egress {
			t.Errorf("value %q: ingress/egress = %v/%v, want %v/%v", tt.value,
				cfg.CommonRuleConfig.TCDefaultDenyIngress, cfg.CommonRuleConfig.TCDefaultDenyEgress, tt.ingress, tt.egress)
		}
	}
}
