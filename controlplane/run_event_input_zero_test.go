package controlplane

import (
	"errors"
	"reflect"
	"testing"
)

var inputDescriptorZeroResult bool

func BenchmarkInputDescriptorZero(b *testing.B) {
	var descriptor ContextInputDescriptor
	b.Run("deep_equal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			inputDescriptorZeroResult = reflect.DeepEqual(descriptor, ContextInputDescriptor{})
		}
	})
	b.Run("is_zero", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			inputDescriptorZeroResult = reflect.ValueOf(descriptor).IsZero()
		}
	})
}

func TestRunEventUnusedInputDescriptorIsExactlyZero(t *testing.T) {
	event := runOpenedEventFixture(t, runPlanFixture(t))
	var visit func(string, reflect.Value)
	var value ContextInputDescriptor
	cases := 0
	check := func(name string, d ContextInputDescriptor) {
		t.Helper()
		want := reflect.DeepEqual(d, ContextInputDescriptor{})
		got := reflect.ValueOf(d).IsZero()
		if got != want {
			t.Fatalf("%s: IsZero=%v DeepEqual=%v", name, got, want)
		}
		changed := event
		changed.inputDescriptor = d
		changed.identity = deriveRunEventIdentity(changed)
		err := changed.Validate()
		if want && err != nil || !want && !errors.Is(err, ErrInvalidRunEventEncoding) {
			t.Fatalf("%s: unexpected event validation error: %v", name, err)
		}
		cases++
	}
	check("zero", ContextInputDescriptor{})
	visit = func(path string, field reflect.Value) {
		switch field.Kind() {
		case reflect.Struct:
			for i := 0; i < field.NumField(); i++ {
				visit(path+"."+field.Type().Field(i).Name, field.Field(i))
			}
		case reflect.String:
			field.SetString("x")
			check(path, value)
			field.SetZero()
		case reflect.Int64:
			field.SetInt(-1)
			check(path, value)
			field.SetZero()
		case reflect.Uint64:
			field.SetUint(1)
			check(path, value)
			field.SetZero()
		case reflect.Slice:
			field.Set(reflect.MakeSlice(field.Type(), 0, 0))
			check(path+".empty", value)
			field.Set(reflect.MakeSlice(field.Type(), 1, 1))
			check(path+".one", value)
			field.SetZero()
		default:
			t.Fatalf("unhandled descriptor field %s: %s", path, field.Kind())
		}
	}
	visit("descriptor", reflect.ValueOf(&value).Elem())
	t.Logf("cases=%d", cases)
}
