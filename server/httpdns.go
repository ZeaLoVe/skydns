// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/mohong122/ip2region/binding/golang"
	"github.com/skynetservices/skydns/cache"
	"github.com/skynetservices/skydns/metrics"
)

var RELOADINTERVAL = 60

func reloadRegionFile(filename string) (*ip2region.Ip2Region, error) {
	ok, err := checkModify(filename)
	if err != nil {
		return nil, err
	} else {
		if !ok {
			return nil, fmt.Errorf("File not changed recently")
		} else {
			return ip2region.New(filename)
		}
	}
}

func checkModify(filename string) (bool, error) {
	if fi, err := os.Stat(filename); err != nil {
		return false, err
	} else {
		if time.Since(fi.ModTime()).Minutes() < float64(RELOADINTERVAL) {
			return true, nil
		} else {
			return false, nil
		}
	}
}

const (
	INIT              = 0
	NOTMATCH          = 1
	BESTMATCH         = 6666
	INNERNET_192      = 1000
	INNERNET_172      = 1001
	INNERNET_10       = 1002
	IPUNKNOWN         = 1003
	GLOBALAWSSINGAPOL = 1010
	GLOBALAWSCA       = 1011
	GLOBALAMERICA     = 1012
	GLOBALAWSEUROP    = 1013
	GLOBALAWSINDIA    = 1014
	GLOBALAWSAFRICA   = 1015
	GLOBALAWSMIDASIA  = 1016
	GLOBALOTHERS      = 1017
	CHINATEL          = 1110
	CHINAUNION        = 1109
	CHINAMOBILE       = 1108
	CHINAOTHERS       = 1107
)

// use this to call dns resolv function
var g_server *server
var g_regions *ip2region.Ip2Region

type SortableIpInfo struct {
	Distance int
	Ip       string
}

type SortableInfos struct {
	CompareType int //request ip region type
	SortList    []SortableIpInfo
}

func getRegionType(ipinfo ip2region.IpInfo) int {
	if ipinfo.CityId == 0 {
		if ipinfo.Country == "中国" {
			if ipinfo.ISP == "电信" {
				return CHINATEL
			} else if ipinfo.ISP == "联通" {
				return CHINAUNION
			} else if ipinfo.ISP == "移动" {
				return CHINAMOBILE
			} else {
				return CHINAOTHERS
			}
		} else if strings.Contains(ipinfo.Country, "192") {
			return INNERNET_192
		} else if strings.Contains(ipinfo.Country, "172") {
			return INNERNET_172
		} else if strings.Contains(ipinfo.Country, "10") {
			return INNERNET_10
		} else {
			return IPUNKNOWN
		}
	}
	return GLOBALAWSSINGAPOL + int(ipinfo.CityId/100)
}

func distance(src, comp int) int {
	if comp == src && comp != IPUNKNOWN {
		return BESTMATCH
	} else {
		return src
	}
}

// sort by distance desc
func (infos SortableInfos) Less(i, j int) bool {
	if g_regions == nil {
		return true
	}
	if infos.SortList[i].Distance == INIT {
		if ipinfo, err := g_regions.MemorySearch(infos.SortList[i].Ip); err != nil {
			infos.SortList[i].Distance = NOTMATCH
		} else {
			infos.SortList[i].Distance = distance(getRegionType(ipinfo), infos.CompareType)
		}
	}
	if infos.SortList[j].Distance == INIT {
		if ipinfo, err := g_regions.MemorySearch(infos.SortList[j].Ip); err != nil {
			infos.SortList[j].Distance = NOTMATCH
		} else {
			infos.SortList[j].Distance = distance(getRegionType(ipinfo), infos.CompareType)
		}
	}

	if infos.SortList[i].Distance < infos.SortList[j].Distance {
		return false
	} else {
		return true
	}
}

func (infos SortableInfos) Swap(i, j int) {
	var tmp SortableIpInfo = infos.SortList[i]
	infos.SortList[i] = infos.SortList[j]
	infos.SortList[j] = tmp
}

func (infos SortableInfos) Len() int {
	return len(infos.SortList)
}

type HttpDnsResult struct {
	Ttl  uint32   `json:"ttl"`
	Host string   `json:"host"`
	Ips  []string `json:"ips"`
}

func (resp HttpDnsResult) Len() int {
	if res, err := json.Marshal(resp); err == nil {
		return len(res)
	}
	return 0
}

type Dto struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	Request_id  string `json:"request_id"`
	Host_id     string `json:"host_id"`
	Server_time string `json:"server_time"`
}

func NewDto() Dto {
	host_name, _ := os.Hostname()
	return Dto{
		Host_id:     host_name,
		Server_time: time.Now().Format(time.RFC3339),
	}
}

func configHttpDns() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	})

	http.HandleFunc("/regions", func(w http.ResponseWriter, r *http.Request) {
		ip := r.FormValue("ip")
		if ip == "" {
			ip = r.RemoteAddr
		}

		ipinfo, _ := g_regions.MemorySearch(ip)
		output := fmt.Sprintf("%v", ipinfo)
		w.Write([]byte(output))
	})

	/*read hosts from config,path:/v2/keys/skydns/hosts/skydns */
	http.HandleFunc("/servers", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/n?host=skydns.hosts", 302)
	})

	http.HandleFunc("/n", func(w http.ResponseWriter, r *http.Request) {
		var resp HttpDnsResult
		resp.Host = r.FormValue("host")
		ip := r.FormValue("ip")
		if resp.Host == "" {
			msg := NewDto()
			msg.Code = "SKYDNS/HOST_MISS"
			msg.Message = "Host name is miss, enter host=XXX in params."
			metrics.ReportHttpErrorCount(metrics.NoHost, metrics.Httpdns)
			RenderJson(w, msg)
			return
		}
		if ip == "" {
			ip = r.RemoteAddr
		}

		m := new(dns.Msg)
		m.Question = append(m.Question, dns.Question{resp.Host, dns.TypeA, dns.ClassINET})
		m.Authoritative = true
		m.RecursionAvailable = true
		m.Compress = true
		dnssec := false
		tcp := false
		bufsize := uint16(512)
		start := time.Now()

		q := m.Question[0]
		name := strings.ToLower(resp.Host)
		metrics.ReportRequestCount(nil, metrics.System(name)) //domain statistic

		// Check cache first.
		m1 := g_server.rcache.Hit(q, dnssec, tcp, m.Id)
		if m1 != nil {
			//hit
			m = m1
		} else {
			//not hit
			records, err := g_server.AddressRecords(q, name, nil, bufsize, dnssec, false)
			if isEtcdNameError(err, g_server) {
				metrics.ReportHttpErrorCount(metrics.Nodata, metrics.Httpdns)
				RenderJson(w, resp)
				return
			}
			m.Answer = append(m.Answer, records...)
			if len(m.Answer) != 0 {
				g_server.rcache.InsertMessage(cache.Key(q, dnssec, tcp), m)
			}
		}

		if len(m.Answer) == 0 { // NODATA response
			RenderJson(w, resp)
			metrics.ReportDurationWithSize(float64(resp.Len()), start, metrics.Httpdns)
			metrics.ReportRequestCount(nil, metrics.Httpdns)
			return
		}

		var ips []string
		resp.Ttl = 3600
		for _, answer := range m.Answer {
			res := answer.String()
			date_len := len(answer.Header().String())
			ips = append(ips, res[date_len:])
			if resp.Ttl > answer.Header().Ttl {
				resp.Ttl = answer.Header().Ttl
			}
		}

		//sort by region infos
		if g_regions != nil {
			ipinfo, _ := g_regions.MemorySearch(ip)
			var infos SortableInfos
			infos.CompareType = getRegionType(ipinfo)
			for _, ip := range ips {
				var info SortableIpInfo
				info.Ip = ip
				infos.SortList = append(infos.SortList, info)
			}
			sort.Sort(infos)
			for i, _ := range ips {
				ips[i] = infos.SortList[i].Ip
			}
		}

		resp.Ips = ips
		RenderJson(w, resp)
		metrics.ReportDurationWithSize(float64(resp.Len()), start, metrics.Httpdns)
		metrics.ReportRequestCount(nil, metrics.Httpdns)
	})
}

func init() {
	configHttpDns()
}

func RenderJson(w http.ResponseWriter, v interface{}) {
	bs, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Write(bs)
}

func (s *server) StartHttp(addr string, regiondb string) error {
	g_server = s

	if addr == "" {
		addr = "127.0.0.1:8053"
	}

	if regiondb == "" {
		regiondb = "./data/ip2region.db"
	}

	httpserver := &http.Server{
		Addr:           addr,
		MaxHeaderBytes: 1 << 30,
	}

	if regions, err := ip2region.New(regiondb); err != nil {
		logf("load region2ip db error:%v", err.Error())
	} else {
		g_regions = regions
		go func() {
			for {
				time.Sleep(time.Duration(RELOADINTERVAL) * time.Minute)
				new_regions, err := reloadRegionFile(regiondb)
				if err == nil {
					g_regions = new_regions
					logf("reload region file success")
				}
			}
		}()
	}

	if err := httpserver.ListenAndServe(); err != nil {
		return err
	}
	return nil
}
