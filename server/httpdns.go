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
)

var RELOADINTERVAL = 60 * 24

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
	INIT         = iota //0
	NOTMATCH            //1
	CANBEMATCH          //2
	MOREMATCH           //3
	FARMOREMATCH        //4
	BESTMATCH           //5
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

/*
use cityId to route
< 100     : "aws新加坡"
100 - 199 : "aws美国加州"
200 - 299 : "aws美洲"
300 - 399 : "aws欧洲"
400 - 499 : "aws印度"
500 - 599 : "aws非洲"
600 - 699 : "aws中亚"
*/
func getZone(id int64) string {
	if id < 100 {
		return "aws新加坡"
	} else if id > 100 && id <= 199 {
		return "aws美国加州"
	} else if id > 200 && id <= 299 {
		return "aws美国加州"
	} else if id > 300 && id <= 399 {
		return "aws欧洲"
	} else if id > 400 && id <= 499 {
		return "aws印度"
	} else if id > 500 && id <= 599 {
		return "aws非洲"
	} else if id > 600 && id <= 699 {
		return "aws中亚"
	} else {
		return "none"
	}
}

func distance(src, comp ip2region.IpInfo) int {
	if comp.CityId == src.CityId {
		//中国 及 内网及未分配
		if comp.CityId == 0 {
			if comp.Country == "中国" && src.Country == "中国" {
				if comp.ISP == "0" || src.ISP == "0" {
					return FARMOREMATCH
				}
				if comp.ISP == src.ISP {
					return BESTMATCH
				}
				return FARMOREMATCH
			} else if comp.Country == src.Country {
				if strings.Contains(comp.Country, "192") || strings.Contains(comp.Country, "172") {
					return BESTMATCH
				} else if strings.Contains(comp.Country, "10") {
					return BESTMATCH
				} else {
					return NOTMATCH
				}
			} else {
				return NOTMATCH
			}
		} else {
			//同一个国家
			return BESTMATCH
		}
	} else {
		if (comp.CityId / 100) == (src.CityId / 100) {
			//不相关区域
			if comp.CityId == 0 || src.CityId == 0 {
				return CANBEMATCH
			}
			//同一个区域
			return BESTMATCH
		} else {
			return CANBEMATCH
		}
	}
	return NOTMATCH
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
			infos.SortList[i].Distance = distance(ipinfo, infos.CompareInfo)
		}
	}
	if infos.SortList[j].Distance == INIT {
		if ipinfo, err := g_regions.MemorySearch(infos.SortList[j].Ip); err != nil {
			infos.SortList[j].Distance = NOTMATCH
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

	http.HandleFunc("/regions", func(w http.ResponseWriter, r *http.Request) {
		ip := r.FormValue("ip")
		if ip == "" {
			ip = r.RemoteAddr
		}

		ipinfo, _ := g_regions.MemorySearch(ip)
		output := fmt.Sprintf("%v", ipinfo)
		w.Write([]byte(output))
	})

	/*read hosts from config,path:/v2/keys/skydns/config/hosts*/
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
			msg.Message = "Please enter host in url arguments, like host=XXX"
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
				logf("cache miss, insert answer")
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
			ipinfo, _ := g_regions.MemorySearch(ip)
			logf("request from: %v", ipinfo)
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
