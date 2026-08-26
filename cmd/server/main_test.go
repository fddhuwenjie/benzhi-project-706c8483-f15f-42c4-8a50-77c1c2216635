package main

import "testing"

func TestParseConfigUsesHighLoopbackDefault(t *testing.T) {
	t.Setenv("PORT", "")
	configuration, err := parseConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if configuration.address != "127.0.0.1:19081" {
		t.Fatalf("address = %s", configuration.address)
	}
}

func TestParseConfigUsesPortOnLoopback(t *testing.T) {
	t.Setenv("PORT", "19444")
	configuration, err := parseConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if configuration.address != "127.0.0.1:19444" {
		t.Fatalf("address = %s", configuration.address)
	}
}

func TestParseConfigRejectsNonLoopback(t *testing.T) {
	t.Setenv("PORT", "")
	if _, err := parseConfig([]string{"-addr=0.0.0.0:19081"}); err == nil {
		t.Fatal("non-loopback address was accepted")
	}
}

func TestParseConfigRejectsInvalidPortEnvironment(t *testing.T) {
	t.Setenv("PORT", "not-a-port")
	if _, err := parseConfig(nil); err == nil {
		t.Fatal("invalid PORT was accepted")
	}
}
