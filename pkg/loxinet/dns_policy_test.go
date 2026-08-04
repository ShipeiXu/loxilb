/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package loxinet

import (
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func TestNormalizeDNSDomain(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "lowercase and trailing dot", input: "  ExAmPlE.CoM. ", want: "example.com"},
		{name: "service label", input: "_sip._udp.example.com", want: "_sip._udp.example.com"},
		{name: "empty", input: "  ", wantErr: true},
		{name: "empty label", input: "example..com", wantErr: true},
		{name: "leading hyphen", input: "-example.com", wantErr: true},
		{name: "trailing hyphen", input: "example-.com", wantErr: true},
		{name: "unicode requires punycode", input: "例子.测试", wantErr: true},
		{name: "label too long", input: strings.Repeat("a", 64) + ".com", wantErr: true},
		{name: "too many labels", input: strings.Repeat("a.", 32) + "a", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeDNSDomain(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("normalizeDNSDomain() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("normalizeDNSDomain() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEncodeDNSDomainSuffixMatching(t *testing.T) {
	policy := encodeDNSDomain("example.com")
	if policy != "com.example." {
		t.Fatalf("encodeDNSDomain() = %q, want %q", policy, "com.example.")
	}

	tests := []struct {
		query string
		want  bool
	}{
		{query: "example.com", want: true},
		{query: "www.example.com", want: true},
		{query: "WWW.Example.COM.", want: true},
		{query: "example.com.evil", want: false},
		{query: "notexample.com", want: false},
	}

	for _, tt := range tests {
		normalized, err := normalizeDNSDomain(tt.query)
		if err != nil {
			t.Fatalf("normalizeDNSDomain(%q): %v", tt.query, err)
		}
		got := strings.HasPrefix(encodeDNSDomain(normalized), policy)
		if got != tt.want {
			t.Errorf("suffix match for %q = %v, want %v", tt.query, got, tt.want)
		}
	}
}

func TestDNSPolicyAction(t *testing.T) {
	if got, err := dnsPolicyAction(cmn.FwOptArg{Allow: true}); err != nil || got != RtActFwd {
		t.Fatalf("allow action = %v, %v", got, err)
	}
	if got, err := dnsPolicyAction(cmn.FwOptArg{Drop: true}); err != nil || got != RtActDrop {
		t.Fatalf("drop action = %v, %v", got, err)
	}
	if got, err := dnsPolicyAction(cmn.FwOptArg{Trap: true}); err != nil || got != RtActTrap {
		t.Fatalf("trap action = %v, %v", got, err)
	}
	if _, err := dnsPolicyAction(cmn.FwOptArg{}); err == nil {
		t.Fatal("missing action should fail")
	}
	if _, err := dnsPolicyAction(cmn.FwOptArg{Allow: true, Drop: true}); err == nil {
		t.Fatal("multiple actions should fail")
	}
}

func TestDNSParserFirewallRules(t *testing.T) {
	rules := dnsParserFwRules()
	if len(rules) != 2 {
		t.Fatalf("dnsParserFwRules() returned %d rules, want 2", len(rules))
	}
	for _, rule := range rules {
		if rule.Proto != 17 || rule.DstPortMin != 53 || rule.DstPortMax != 53 || rule.Pref != DnsParserFwPref {
			t.Errorf("unexpected DNS parser rule: %+v", rule)
		}
	}
}
