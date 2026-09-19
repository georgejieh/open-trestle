package provider

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestProviderZoneRoundTrips(t *testing.T) {
	zones := []struct {
		zone ProviderZone
		name string
	}{
		{ProviderZoneLocal, "local"},
		{ProviderZonePrivateRemote, "private_remote"},
		{ProviderZoneBrokeredRemote, "brokered_remote"},
		{ProviderZoneSubscriptionOAuth, "subscription_oauth"},
	}
	for _, test := range zones {
		parsed, err := ParseProviderZone(test.name)
		if err != nil || parsed != test.zone || parsed.String() != test.name {
			t.Fatalf("zone %q round trip = (%v, %v, %q)", test.name, parsed, err, parsed.String())
		}
	}
	for _, value := range []string{"", "LOCAL", " local", "local ", "remote", "private-remote"} {
		if zone, err := ParseProviderZone(value); !errors.Is(err, ErrInvalidProviderZone) || zone != 0 {
			t.Fatalf("ParseProviderZone(%q) = (%v, %v)", value, zone, err)
		}
	}
	if ProviderZone(99).String() != "" {
		t.Fatal("unknown zone has a token")
	}
}

func TestNewRouteReferencePreservesExactIdentifiers(t *testing.T) {
	route, err := NewRouteReference(ProviderZoneLocal, "local", "openai-compatible", "primary/local", "Qwen2.5-Coder", "32B-q4")
	if err != nil {
		t.Fatal(err)
	}
	if route.Zone() != ProviderZoneLocal || route.ProviderID() != "local" || route.AdapterID() != "openai-compatible" || route.ConnectionID() != "primary/local" || route.ModelID() != "Qwen2.5-Coder" || route.ModelVersion() != "32B-q4" {
		t.Fatalf("route fields do not round trip")
	}
	copied := route
	if copied != route || copied.Validate() != nil {
		t.Fatal("copied route changed")
	}
}

func TestRouteReferenceAllowsUnboundModelVersion(t *testing.T) {
	route, err := NewRouteReference(ProviderZonePrivateRemote, "vendor", "direct-api", "primary", "Model-A", "")
	if err != nil || route.ModelVersion() != "" || route.Validate() != nil {
		t.Fatalf("unversioned route = (%#v, %v)", route, err)
	}
}

func TestRouteReferenceEqualityBindsEveryField(t *testing.T) {
	base, _ := NewRouteReference(ProviderZoneLocal, "provider", "adapter", "connection", "Model", "Version")
	alternates := []RouteReference{}
	values := []struct {
		zone         ProviderZone
		providerID   string
		adapterID    string
		connectionID string
		modelID      string
		modelVersion string
	}{
		{ProviderZonePrivateRemote, "provider", "adapter", "connection", "Model", "Version"},
		{ProviderZoneLocal, "other", "adapter", "connection", "Model", "Version"},
		{ProviderZoneLocal, "provider", "other", "connection", "Model", "Version"},
		{ProviderZoneLocal, "provider", "adapter", "other", "Model", "Version"},
		{ProviderZoneLocal, "provider", "adapter", "connection", "Other", "Version"},
		{ProviderZoneLocal, "provider", "adapter", "connection", "Model", "Other"},
		{ProviderZoneLocal, "provider", "adapter", "connection", "Model", ""},
	}
	for _, value := range values {
		route, err := NewRouteReference(value.zone, value.providerID, value.adapterID, value.connectionID, value.modelID, value.modelVersion)
		if err != nil {
			t.Fatal(err)
		}
		alternates = append(alternates, route)
	}
	for index, route := range alternates {
		if route == base {
			t.Fatalf("alternate %d equals base", index)
		}
	}
}

func TestRouteReferenceFormattingRedactsLabels(t *testing.T) {
	route, _ := NewRouteReference(ProviderZoneLocal, "provider", "adapter", "sensitive-connection", "Model", "Version")
	for _, format := range []string{"%v", "%+v", "%#v"} {
		formatted := fmt.Sprintf(format, route)
		if strings.Contains(formatted, "sensitive-connection") {
			t.Fatalf("format %s exposed connection label", format)
		}
	}
}

func TestRouteReferenceIdentifierBoundaries(t *testing.T) {
	providerID := "p" + strings.Repeat("x", maxProviderIDBytes-1)
	adapterID := "a" + strings.Repeat("x", maxProviderAdapterIDBytes-1)
	connectionID := "c" + strings.Repeat("x", maxProviderConnectionIDBytes-1)
	modelID := "m" + strings.Repeat("x", maxProviderModelIDBytes-1)
	modelVersion := "v" + strings.Repeat("x", maxProviderModelVersionBytes-1)
	route, err := NewRouteReference(ProviderZoneBrokeredRemote, providerID, adapterID, connectionID, modelID, modelVersion)
	if err != nil || route.ProviderID() != providerID || route.AdapterID() != adapterID || route.ConnectionID() != connectionID || route.ModelID() != modelID || route.ModelVersion() != modelVersion {
		t.Fatalf("boundary route invalid: %v", err)
	}
}

func TestNewRouteReferenceRejectsInvalidFields(t *testing.T) {
	valid := func() (ProviderZone, string, string, string, string, string) {
		return ProviderZoneLocal, "provider", "adapter", "connection", "Model", "Version"
	}
	for _, test := range []struct {
		name   string
		mutate func(*ProviderZone, *string, *string, *string, *string, *string)
		want   error
	}{
		{name: "zone", mutate: func(z *ProviderZone, _ *string, _ *string, _ *string, _ *string, _ *string) { *z = 0 }, want: ErrInvalidProviderZone},
		{name: "provider empty", mutate: func(_ *ProviderZone, v *string, _ *string, _ *string, _ *string, _ *string) { *v = "" }, want: ErrInvalidProviderID},
		{name: "provider uppercase", mutate: func(_ *ProviderZone, v *string, _ *string, _ *string, _ *string, _ *string) { *v = "Provider" }, want: ErrInvalidProviderID},
		{name: "provider long", mutate: func(_ *ProviderZone, v *string, _ *string, _ *string, _ *string, _ *string) {
			*v = strings.Repeat("p", maxProviderIDBytes+1)
		}, want: ErrInvalidProviderID},
		{name: "adapter uppercase", mutate: func(_ *ProviderZone, _ *string, v *string, _ *string, _ *string, _ *string) { *v = "Adapter" }, want: ErrInvalidAdapterID},
		{name: "adapter punctuation", mutate: func(_ *ProviderZone, _ *string, v *string, _ *string, _ *string, _ *string) { *v = "-adapter" }, want: ErrInvalidAdapterID},
		{name: "connection space", mutate: func(_ *ProviderZone, _ *string, _ *string, v *string, _ *string, _ *string) { *v = "connection id" }, want: ErrInvalidConnectionID},
		{name: "connection control", mutate: func(_ *ProviderZone, _ *string, _ *string, v *string, _ *string, _ *string) {
			*v = "connection\nsecret"
		}, want: ErrInvalidConnectionID},
		{name: "connection double slash", mutate: func(_ *ProviderZone, _ *string, _ *string, v *string, _ *string, _ *string) { *v = "group//connection" }, want: ErrInvalidConnectionID},
		{name: "connection digit child", mutate: func(_ *ProviderZone, _ *string, _ *string, v *string, _ *string, _ *string) { *v = "group/9child" }, want: ErrInvalidConnectionID},
		{name: "connection dash child", mutate: func(_ *ProviderZone, _ *string, _ *string, v *string, _ *string, _ *string) { *v = "group/-child" }, want: ErrInvalidConnectionID},
		{name: "connection dot child", mutate: func(_ *ProviderZone, _ *string, _ *string, v *string, _ *string, _ *string) { *v = "group/.child" }, want: ErrInvalidConnectionID},
		{name: "connection underscore child", mutate: func(_ *ProviderZone, _ *string, _ *string, v *string, _ *string, _ *string) { *v = "group/_child" }, want: ErrInvalidConnectionID},
		{name: "connection trailing slash", mutate: func(_ *ProviderZone, _ *string, _ *string, v *string, _ *string, _ *string) { *v = "group/" }, want: ErrInvalidConnectionID},
		{name: "connection long", mutate: func(_ *ProviderZone, _ *string, _ *string, v *string, _ *string, _ *string) {
			*v = strings.Repeat("c", maxProviderConnectionIDBytes+1)
		}, want: ErrInvalidConnectionID},
		{name: "model nonascii", mutate: func(_ *ProviderZone, _ *string, _ *string, _ *string, v *string, _ *string) { *v = "Mødel" }, want: ErrInvalidModelID},
		{name: "model query", mutate: func(_ *ProviderZone, _ *string, _ *string, _ *string, v *string, _ *string) { *v = "model?token=value" }, want: ErrInvalidModelID},
		{name: "model slash prefix", mutate: func(_ *ProviderZone, _ *string, _ *string, _ *string, v *string, _ *string) { *v = "/model" }, want: ErrInvalidModelID},
		{name: "model endpoint", mutate: func(_ *ProviderZone, _ *string, _ *string, _ *string, v *string, _ *string) {
			*v = "https://user:token@evil.example/v1"
		}, want: ErrInvalidModelID},
		{name: "model opaque URI", mutate: func(_ *ProviderZone, _ *string, _ *string, _ *string, v *string, _ *string) {
			*v = "https:evil.example"
		}, want: ErrInvalidModelID},
		{name: "model host port", mutate: func(_ *ProviderZone, _ *string, _ *string, _ *string, v *string, _ *string) { *v = "evil.example:443" }, want: ErrInvalidModelID},
		{name: "model IP port", mutate: func(_ *ProviderZone, _ *string, _ *string, _ *string, v *string, _ *string) { *v = "127.0.0.1:8080" }, want: ErrInvalidModelID},
		{name: "model double slash", mutate: func(_ *ProviderZone, _ *string, _ *string, _ *string, v *string, _ *string) { *v = "org//model" }, want: ErrInvalidModelID},
		{name: "model dot segment", mutate: func(_ *ProviderZone, _ *string, _ *string, _ *string, v *string, _ *string) { *v = "org/../model" }, want: ErrInvalidModelID},
		{name: "model embedded version", mutate: func(_ *ProviderZone, _ *string, _ *string, _ *string, v *string, _ *string) { *v = "Model@v1" }, want: ErrInvalidModelID},
		{name: "model repeated tag", mutate: func(_ *ProviderZone, _ *string, _ *string, _ *string, v *string, _ *string) { *v = "Model:v1:v2" }, want: ErrInvalidModelID},
		{name: "model long", mutate: func(_ *ProviderZone, _ *string, _ *string, _ *string, v *string, _ *string) {
			*v = strings.Repeat("m", maxProviderModelIDBytes+1)
		}, want: ErrInvalidModelID},
		{name: "version space", mutate: func(_ *ProviderZone, _ *string, _ *string, _ *string, _ *string, v *string) { *v = "version one" }, want: ErrInvalidModelVersion},
		{name: "version endpoint", mutate: func(_ *ProviderZone, _ *string, _ *string, _ *string, _ *string, v *string) {
			*v = "https://evil.example/v1"
		}, want: ErrInvalidModelVersion},
		{name: "version path", mutate: func(_ *ProviderZone, _ *string, _ *string, _ *string, _ *string, v *string) { *v = "version/path" }, want: ErrInvalidModelVersion},
		{name: "version at", mutate: func(_ *ProviderZone, _ *string, _ *string, _ *string, _ *string, v *string) { *v = "version@tag" }, want: ErrInvalidModelVersion},
		{name: "version colon", mutate: func(_ *ProviderZone, _ *string, _ *string, _ *string, _ *string, v *string) { *v = "version:tag" }, want: ErrInvalidModelVersion},
		{name: "version long", mutate: func(_ *ProviderZone, _ *string, _ *string, _ *string, _ *string, v *string) {
			*v = strings.Repeat("v", maxProviderModelVersionBytes+1)
		}, want: ErrInvalidModelVersion},
	} {
		t.Run(test.name, func(t *testing.T) {
			zone, providerID, adapterID, connectionID, modelID, modelVersion := valid()
			test.mutate(&zone, &providerID, &adapterID, &connectionID, &modelID, &modelVersion)
			route, err := NewRouteReference(zone, providerID, adapterID, connectionID, modelID, modelVersion)
			if !errors.Is(err, test.want) || route != (RouteReference{}) {
				t.Fatalf("NewRouteReference() returned %v, want %v", err, test.want)
			}
		})
	}
}

func TestRouteReferenceZeroAndForgedValuesFailValidation(t *testing.T) {
	valid := RouteReference{zone: ProviderZoneLocal, providerID: "p", adapterID: "a", connectionID: "c", modelID: "m"}
	for _, test := range []struct {
		name  string
		route RouteReference
		want  error
	}{
		{name: "zero", want: ErrInvalidProviderZone},
		{name: "zone", route: RouteReference{zone: ProviderZone(99), providerID: "p", adapterID: "a", connectionID: "c", modelID: "m"}, want: ErrInvalidProviderZone},
		{name: "provider", route: RouteReference{zone: valid.zone, adapterID: valid.adapterID, connectionID: valid.connectionID, modelID: valid.modelID}, want: ErrInvalidProviderID},
		{name: "adapter", route: RouteReference{zone: valid.zone, providerID: valid.providerID, connectionID: valid.connectionID, modelID: valid.modelID}, want: ErrInvalidAdapterID},
		{name: "connection", route: RouteReference{zone: valid.zone, providerID: valid.providerID, adapterID: valid.adapterID, modelID: valid.modelID}, want: ErrInvalidConnectionID},
		{name: "model", route: RouteReference{zone: valid.zone, providerID: valid.providerID, adapterID: valid.adapterID, connectionID: valid.connectionID, modelID: "m id"}, want: ErrInvalidModelID},
		{name: "version", route: RouteReference{zone: valid.zone, providerID: valid.providerID, adapterID: valid.adapterID, connectionID: valid.connectionID, modelID: valid.modelID, modelVersion: "v id"}, want: ErrInvalidModelVersion},
	} {
		if err := test.route.Validate(); !errors.Is(err, test.want) {
			t.Fatalf("%s Validate() = %v, want %v", test.name, err, test.want)
		}
	}
}

func TestRouteReferenceSurfaceContainsOnlyOpaqueSelectionLabels(t *testing.T) {
	typeOfRoute := reflect.TypeOf(RouteReference{})
	want := []string{"zone", "providerID", "adapterID", "connectionID", "modelID", "modelVersion"}
	if typeOfRoute.NumField() != len(want) {
		t.Fatalf("RouteReference has %d fields, want %d", typeOfRoute.NumField(), len(want))
	}
	for index, name := range want {
		field := typeOfRoute.Field(index)
		if field.Name != name {
			t.Fatalf("field %d = %q, want %q", index, field.Name, name)
		}
		if index > 0 && field.Type.Kind() != reflect.String {
			t.Fatalf("field %s type = %s, want string", field.Name, field.Type)
		}
	}
}

func TestValidateAdapterIDUsesRouteRegistryGrammar(t *testing.T) {
	for _, value := range []string{"openai", "openai.compat-v1", "local_adapter"} {
		if err := ValidateAdapterID(value); err != nil {
			t.Fatalf("ValidateAdapterID(%q) = %v", value, err)
		}
	}
	for _, value := range []string{"", "Upper", "has/slash", strings.Repeat("a", maxProviderAdapterIDBytes+1)} {
		if err := ValidateAdapterID(value); !errors.Is(err, ErrInvalidAdapterID) {
			t.Fatalf("ValidateAdapterID(%q) = %v", value, err)
		}
	}
}
