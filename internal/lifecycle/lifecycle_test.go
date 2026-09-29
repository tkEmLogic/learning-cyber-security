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

func revoked() Record {
	return Record{Kind: KindRevocation, DeviceID: device}
}

// Every one of the six states, each from the log that reaches it.
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
		{"a revocation makes it revoked",
			[]Record{enrolled(), claimed("northwind", "7009"), revoked()}, Revoked},
		{"a revocation of an active device makes it revoked",
			[]Record{enrolled(), claimed("northwind", "7009"), activated("7009"), revoked()}, Revoked},
		{"only a remanufacture leaves revoked",
			[]Record{enrolled(), claimed("northwind", "7009"), revoked(),
				{Kind: KindRemanufacture, DeviceID: device}}, Manufactured},
		{"a transfer makes it transferred",
			[]Record{enrolled(), claimed("northwind", "7009"), activated("7009"),
				{Kind: KindTransfer, DeviceID: device, OwnerID: "northwind"}}, Transferred},
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
		{"a revocation of a device the log has never seen",
			[]Record{revoked()}, ""},
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
	// A revoked device is no longer owned, but the owner of record stays on it
	// so owner-of-record can still say whose device was stopped.
	log = append(log, revoked())
	if got := Derive(log)[device]; got.Owned() || got.Owner != "northwind" {
		t.Fatalf("revoked device = %#v", got)
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

func recovered(owner, serial string) Record {
	return Record{Kind: KindRecovery, DeviceID: device, OwnerID: owner, CertSerial: serial}
}

// Recovery changes no state, as ADR 0003 says: a device that lost its key is
// still where the log left it. What it does change is which certificates the
// device holds, so the new one can be activated.
func TestARecoveryMovesNoStateAndAddsTheNewCertificate(t *testing.T) {
	authorized := Record{Kind: KindRecoveryAuthorization, DeviceID: device, OwnerID: "northwind"}
	cases := []struct {
		name    string
		records []Record
		want    string
	}{
		{"a claimed device stays claimed",
			[]Record{enrolled(), claimed("northwind", "7009"), authorized, recovered("northwind", "7010")}, Claimed},
		{"an active device stays active",
			[]Record{enrolled(), claimed("northwind", "7009"), activated("7009"), authorized,
				recovered("northwind", "7010")}, Active},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Derive(c.records)[device]
			if got.State != c.want {
				t.Fatalf("state = %q, want %q", got.State, c.want)
			}
			if !got.Operational["7010"] || got.Owner != "northwind" {
				t.Fatalf("the recovered certificate must join the device under its owner: %#v", got)
			}
		})
	}

	// The recovered certificate's first use is an activation like any other.
	after := Derive([]Record{enrolled(), claimed("northwind", "7009"), recovered("northwind", "7010"),
		activated("7010")})[device]
	if after.State != Active || !after.Activated["7010"] {
		t.Fatalf("the recovered certificate's first use must activate it: %#v", after)
	}
}

// A recovery that names somebody other than the owner of record, or a device
// nobody owns, adds nothing.
func TestARecoveryForAnotherOwnerAddsNothing(t *testing.T) {
	for name, records := range map[string][]Record{
		"another owner":     {enrolled(), claimed("northwind", "7009"), recovered("contoso", "7010")},
		"an unowned device": {enrolled(), recovered("northwind", "7010")},
		"a revoked device":  {enrolled(), claimed("northwind", "7009"), revoked(), recovered("northwind", "7010")},
	} {
		t.Run(name, func(t *testing.T) {
			if Derive(records)[device].Operational["7010"] {
				t.Fatal("a recovery that is not a transition must add no certificate")
			}
		})
	}
}

func transferred(owner string) Record {
	return Record{Kind: KindTransfer, DeviceID: device, OwnerID: owner}
}

// A transfer is a resting state, as #215 settled against #205: the device is
// owned by no one until a new owner claims it, and the new claim starts a
// certificate history of its own.
func TestATransferRestsUntilTheNextClaim(t *testing.T) {
	log := []Record{enrolled(), claimed("northwind", "7009"), activated("7009"), transferred("northwind")}
	got := Derive(log)[device]
	if got.State != Transferred || got.Owned() || got.Owner != "" || got.Operational["7009"] {
		t.Fatalf("transferred device = %#v, want transferred and owned by no one", got)
	}
	if StateAfter(log[:3], transferred("northwind")) != Transferred {
		t.Fatal("a transfer line must store transferred")
	}

	log = append(log, claimed("contoso", "7020"))
	got = Derive(log)[device]
	if got.State != Claimed || got.Owner != "contoso" || !got.Operational["7020"] || got.Operational["7009"] {
		t.Fatalf("after the new claim: %#v, want claimed by contoso with only the new certificate", got)
	}
}

// Only the owner of record gives a device up. A transfer naming somebody else,
// of a device nobody owns, or of a revoked device moves nothing.
func TestATransferThatIsNotATransitionMovesNothing(t *testing.T) {
	for name, c := range map[string]struct {
		records []Record
		want    string
	}{
		"another owner":     {[]Record{enrolled(), claimed("northwind", "7009"), transferred("contoso")}, Claimed},
		"an unowned device": {[]Record{enrolled(), transferred("northwind")}, Manufactured},
		"a revoked device":  {[]Record{enrolled(), claimed("northwind", "7009"), revoked(), transferred("northwind")}, Revoked},
		"twice":             {[]Record{enrolled(), claimed("northwind", "7009"), transferred("northwind"), transferred("northwind")}, Transferred},
	} {
		t.Run(name, func(t *testing.T) {
			if got := Derive(c.records)[device].State; got != c.want {
				t.Fatalf("state = %q, want %q", got, c.want)
			}
		})
	}
}
