package main

import (
	"flag"
	"math/rand"
	"os"
	"testing"
	"time"

	"k8s.io/klog"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	acmetest "github.com/cert-manager/cert-manager/test/acme"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
)

const letterBytes = "abcdefghijklmnopqrstuvwxyz0123456789"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
func TestRunsSuite(t *testing.T) {
	// The manifest path should contain a file named config.json that is a
	// snippet of valid configuration that should be included on the
	// ChallengeRequest passed as part of the test cases.
	//

	klog.InitFlags(nil)
	flag.Set("logtostderr", "true")
	flag.Set("stderrthreshold", "WARNING")
	flag.Set("v", "5")

	key := "ax7fyx"                 //RandStringBytes(6) //"gvhz3v"
	dnsServer := "ns1.loopia.se:53" //"8.8.8.8:53"
	authoritative := false

	// Uncomment the below fixture when implementing your custom DNS provider
	fixture := acmetest.NewFixture(&customDNSProviderSolver{},
		acmetest.SetResolvedZone(zone),
		acmetest.SetAllowAmbientCredentials(false),
		acmetest.SetManifestPath("testdata/loopia"),
		acmetest.SetUseAuthoritative(authoritative),
		acmetest.SetDNSChallengeKey(key),
		acmetest.SetDNSServer(dnsServer),
		acmetest.SetPollInterval(time.Second*60),
		acmetest.SetPropagationLimit(time.Minute*30),
	)
	//need to uncomment and  RunConformance delete runBasic and runExtended once https://github.com/cert-manager/cert-manager/pull/4835 is merged
	//fixture.RunConformance(t)
	//fixture.RunBasic(t)
	//fixture.RunExtended(t)

	result, err := util.PreCheckDNS("cert-manager-dns01-tests.sqv.st.", key, []string{dnsServer}, authoritative)
	klog.V(2).Infoln(result, err)

	fixture.RunBasic(t)
}
