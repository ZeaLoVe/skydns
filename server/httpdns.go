// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package server

import (
	"encoding/json"
	"net/http"
	_ "net/http/pprof"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/mohong122/ip2region/binding/golang"
	"github.com/skynetservices/skydns/cache"
)

// use this to call dns resolv function
var g_server *server
var g_regions *ip2region.Ip2Region

type SortInfo struct {
	Distance int
	Ip       string
}

type SortableInfos struct {
	CompareInfo ip2region.IpInfo //region info of source ip
	SortList    []SortInfo
}

func distance(src, comp ip2region.IpInfo) int {
	if comp.Country == src.Country {
		if comp.Country == "中国" {
			if comp.ISP == "0" || src.ISP == "0" {
				return 2
			}
			if comp.ISP == src.ISP {
				return 5
			}
		}
		return 2
	} else {
		return 1
	}
}

// sort by distance desc
func (infos SortableInfos) Less(i, j int) bool {
	if g_regions == nil {
		return true
	}
	if infos.SortList[i].Distance == 0 {
		if ipinfo, err := g_regions.MemorySearch(infos.SortList[i].Ip); err != nil {
			infos.SortList[i].Distance = 1
		} else {
			infos.SortList[i].Distance = distance(ipinfo, infos.CompareInfo)
		}
	}
	if infos.SortList[j].Distance == 0 {
		if ipinfo, err := g_regions.MemorySearch(infos.SortList[j].Ip); err != nil {
			infos.SortList[j].Distance = 1
		} else {
			infos.SortList[j].Distance = distance(ipinfo, infos.CompareInfo)
		}
	}

	if infos.SortList[i].Distance < infos.SortList[j].Distance {
		return false
	} else {
		return true
	}
}

func (infos SortableInfos) Swap(i, j int) {
	var tmp SortInfo = infos.SortList[i]
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

	http.HandleFunc("/servers", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("servers\n"))
	})

	http.HandleFunc("/ip2region/reload", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("reload\n"))
	})

	http.HandleFunc("/n", func(w http.ResponseWriter, r *http.Request) {
		var resp HttpDnsResult
		resp.Host = r.FormValue("host")
		ip := r.FormValue("ip")
		if resp.Host == "" {
			msg := NewDto()
			msg.Code = "SKYDNS/HOST_MISS"
			msg.Message = "Please enter host in url arguments, like host=XXX"
			RenderJson(w, msg)
			return
		}
		if ip == "" {
			ip = r.RemoteAddr
		}

		ipinfo, _ := g_regions.MemorySearch(ip)
		logf("ipinfo: %v", ipinfo)

		m := new(dns.Msg)
		m.Question = append(m.Question, dns.Question{resp.Host, dns.TypeA, dns.ClassINET})
		m.Authoritative = true
		m.RecursionAvailable = true
		m.Compress = true
		dnssec := false
		tcp := false
		bufsize := uint16(512)
		//		start := time.Now() // record time

		q := m.Question[0]
		name := strings.ToLower(resp.Host)

		// Check cache first.
		m1 := g_server.rcache.Hit(q, dnssec, tcp, m.Id)
		if m1 != nil {
			//hit
			logf("cache hit")
			m = m1
		} else {
			//not hit
			records, err := g_server.AddressRecords(q, name, nil, bufsize, dnssec, false)
			if isEtcdNameError(err, g_server) {
				RenderJson(w, resp)
				return
			}
			m.Answer = append(m.Answer, records...)
			if len(m.Answer) != 0 {
				logf("cache insert")
				g_server.rcache.InsertMessage(cache.Key(q, dnssec, tcp), m)
			}
		}

		if len(m.Answer) == 0 { // NODATA response
			RenderJson(w, resp)
			return
		}

		var ips []string
		resp.Ttl = 3600
		for _, answer := range m.Answer {
			res := answer.String()
			date_len := len(answer.Header().String())
			//			logf("date len: %v , total len:%v", date_len, length)
			ips = append(ips, res[date_len:])
			if resp.Ttl > answer.Header().Ttl {
				resp.Ttl = answer.Header().Ttl
			}
		}

		//sort by region infos
		if g_regions != nil {
			var infos SortableInfos
			infos.CompareInfo = ipinfo
			for _, ip := range ips {
				var info SortInfo
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
	}

	if err := httpserver.ListenAndServe(); err != nil {
		return err
	}
	return nil
}
