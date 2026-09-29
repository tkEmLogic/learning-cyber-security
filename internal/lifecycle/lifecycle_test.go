package lifecycle

import "testing"

const device = "beacon-remfg-206ef1170d64"

func enrolled() Record {
	return Record{Kind: KindEnrollment, DeviceID: device, Result: "issued"}
}

func claimed(owner, serial string) Record {
	return Record{Kind: KindClaim, DeviceID: device, OwnerID: owner, CertSerial: serial}
}

func activated(serial string) Record {
	return Record{Kind: KindActivation, DeviceID: device, CertSerial: serial}
}

// Every state reachable so far, each from the log that reaches it. The other
// three states are declared and have no transition into them yet, which is
// what the later Tier 8 tickets build.
func TestEachReachableStateIsDerivedFromTheLog(t *testing.T) {
	cases := []struct {
		name    string
		records []Record
		want    string
	}{
		{"enrollment makes a device manufactured", []Record{enrolled()}, Manufactured},
		{"a claim makes it claimed", []Record{enrolled(), claimed("northwind", "7009")}, Claimed},
		{"first use makes it active", []Record{enrolled(), claimed("northwind", "7009"), activated("7009")}, Active},
		{"remanufacture takes it back to manufactured",
			[]Record{enrolled(), claimed("northwind", "7009"), activated("7009"),
				{Kind: KindRemanufacture, DeviceID: device}}, Manufactured},
		{"decommission retires it from any state",
			[]Record{enrolled(), claimed("northwind", "7009"), activated("7009"),
				{Kind: KindDecommission, DeviceID: device}}, Decommissioned},
		{"remanufacture is the way back out of decommissioned",
			[]Record{enrolled(), claimed("northwind", "7009"),
				{Kind: KindDecommission, DeviceID: device},
				{Kind: KindRemanufacture, DeviceID: device}}, Manufactured},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Derive(c.records)[device].State; got != c.want {
				t.Fatalf("state = %q, want %q", got, c.want)
			}
		})
	}
}

// Lines that describe no transition from where the device stands move
// nothing. The log is append only and has two writers, so it can hold them.
func TestALineThatIsNotATransitionMovesNothing(t *testing.T) {
	cases := []struct {
		name    string
		records []Record
		want    string
	}{
		{"a refused enrollment manufactures nothing",
			[]Record{{Kind: KindEnrollment, DeviceID: device, Result: "refused"}}, ""},
		{"an activation before any claim",
			[]Record{enrolled(), activated("7009")}, Manufactured},
		{"an activation for a serial this device was never issued",
			[]Record{enrolled(), claimed("northwind", "7009"), activated("9999")}, Claimed},
		{"an activation for a certificate from an earlier claim",
			[]Record{enrolled(), claimed("northwind", "7009"),
				{Kind: KindRemanufacture, DeviceID: device}, claimed("contoso", "8001"), activated("7009")}, Claimed},
		{"a line of a kind that moves no state",
			[]Record{enrolled(), claimed("northwind", "7009"), {Kind: "credential_issued", DeviceID: device}}, Claimed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Derive(c.records)[device].State; got != c.want {
				t.Fatalf("state = %q, want %q", got, c.want)
			}
		})
	}
}

// Ownership is derived alongside the state, and a device has an owner only
// while it is claimed or active.
func TestOwnershipFollowsTheState(t *testing.T) {
	log := []Record{enrolled()}
	if Derive(log)[device].Owned() {
		t.Fatal("a manufactured device has no owner")
	}
	log = append(log, claimed("northwind", "7009"))
	if got := Derive(log)[device]; !got.Owned() || got.Owner != "northwind" {
		t.Fatalf("claimed device = %#v", got)
	}
	log = append(log, activated("7009"))
	if got := Derive(log)[device]; !got.Owned() || got.Owner != "northwind" {
		t.Fatalf("active device = %#v", got)
	}
}

// Activation is once per certificate, and the derivation is what says whether
// one is still owed.
func TestActivationIsRecordedOncePerCertificate(t *testing.T) {
	log := []Record{enrolled(), claimed("northwind", "7009")}
	if Derive(log)[device].Activated["7009"] {
		t.Fatal("an issued certificate is not yet a used one")
	}
	log = append(log, activated("7009"))
	if !Derive(log)[device].Activated["7009"] {
		t.Fatal("the activation was not derived")
	}
}

// The field a writer stores is the derivation's answer, so it cannot
// disagree with the log.
func TestStateAfterIsTheDerivationOfTheLogWithTheLineOnIt(t *testing.T) {
	log := []Record{enrolled()}
	if got := StateAfter(nil, enrolled()); got != Manufactured {
		t.Fatalf("enrollment writes %q, want %q", got, Manufactured)
	}
	if got := StateAfter(log, claimed("northwind", "7009")); got != Claimed {
		t.Fatalf("claim writes %q, want %q", got, Claimed)
	}
	log = append(log, claimed("northwind", "7009"))
	if got := StateAfter(log, activated("7009")); got != Active {
		t.Fatalf("activation writes %q, want %q", got, Active)
	}
}
