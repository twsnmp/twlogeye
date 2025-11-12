package datastore

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/domainr/dnsr"
	"github.com/oschwald/geoip2-golang"
)

var ip2HostMap sync.Map
var ip2LocMap sync.Map
var geoipDB *geoip2.Reader
var dnsResolver *dnsr.Resolver

func SetupIPInfoDB() (bool, bool) {
	var err error
	if Config.GeoIPDB != "" {
		geoipDB, err = geoip2.Open(Config.GeoIPDB)
		if err != nil {
			log.Fatalln(err)
		}
	}
	if Config.ResolveHostName {
		dnsResolver = dnsr.NewWithTimeout(10000, time.Millisecond*1000)
	}
	return geoipDB != nil, dnsResolver != nil
}

func GetLocByIP(sip string) string {
	if v, ok := ip2LocMap.Load(sip); ok {
		return v.(string)
	}
	ip := net.ParseIP(sip)
	r, err := geoipDB.City(ip)
	if err != nil || r.Country.IsoCode == "" {
		ip2LocMap.Store(sip, "")
		return ""
	}
	loc := fmt.Sprintf("%s:%s:%0.3f,%0.3f", r.Country.IsoCode, r.City.Names["en"], r.Location.Latitude, r.Location.Longitude)
	ip2LocMap.Store(sip, loc)
	return loc
}

func GetHostByIP(sip string) string {
	if v, ok := ip2HostMap.Load(sip); ok {
		return v.(string)
	}
	a := strings.SplitN(sip, ".", 4)
	if len(a) == 4 {
		for _, rr := range dnsResolver.Resolve(fmt.Sprintf("%s.%s.%s.%s.in-addr.arpa", a[3], a[2], a[1], a[0]), "PTR") {
			if rr.Type == "PTR" {
				ip2HostMap.Store(sip, rr.Value)
				return rr.Value
			}
		}
	} else {
		// IPv6
		ip := net.ParseIP(sip)
		ip16 := ip.To16()
		if ip16 != nil {
			var s string
			for i := 15; i >= 0; i-- {
				b := ip16[i]
				s += fmt.Sprintf("%x.%x.", b&0x0f, b>>4)
			}
			s += "ip6.arpa"
			for _, rr := range dnsResolver.Resolve(s, "PTR") {
				if rr.Type == "PTR" {
					ip2HostMap.Store(sip, rr.Value)
					return rr.Value
				}
			}
		}
	}
	ip2HostMap.Store(sip, "")
	return ""
}
