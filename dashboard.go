package main

// dashboard.go exposes a per-game /api/stats JSON for the unified Nextendo
// monitoring site (nextendo-dashboard, :8085). The aggregator polls this endpoint,
// tags it "mk8" and rolls it into the global view. the game server keeps all state in memory
// (no Postgres), so we read the live gatherings + connections through the nex
// package's read-only Snapshot accessors, plus lightweight RMC counters fed from
// the endpoint's OnRMC hook. JSON keys mirror the proven mk8 dashboard so the
// existing aggregator UI renders it unchanged.

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	nex "github.com/NextendoNetwork/nextendo-nex"
)

var (
	dashStart = time.Now()

	metaMu        sync.Mutex
	playerMeta    = map[uint64]*playerInfo{}
	sessionsSeen  int64
	peakConnected int

	rmcTotal int64

	eventsMu    sync.Mutex
	events      []rmcEvent // ring buffer of recent RMC calls (newest last)
	methodCount = map[string]int64{}
)

type playerInfo struct {
	PID        uint64
	FirstSeen  time.Time
	LastSeen   time.Time
	IP         string
	Calls      int64
	LastProto  uint16
	LastMethod uint32
	NATMap     uint32 // NAT mapping behaviour (from NATTraversal ReportNATProperties)
	NATFilter  uint32 // NAT filtering behaviour
	Ping       uint32 // RTT in ms the client reported (0 = unknown)
}

type rmcEvent struct {
	T      time.Time
	PID    uint64
	Proto  uint16
	Method uint32
}

// ghostIdle : au-delà de cette inactivité RMC, une connexion PRUDP encore ouverte (le client
// continue d'envoyer des PING) est considérée FANTÔME et n'est plus comptée « en ligne » par
// le monitoring. Sans ce seuil, un émulateur/une console laissé ouvert pingue pendant des
// jours et s'affichait « en ligne depuis 100 h ». Même notion de fantôme que la garde « un
// seul endroit » côté compte (env NEXTENDO_GHOST_IDLE_SECONDS, défaut 15 min).
func ghostIdle() time.Duration {
	if n, err := strconv.Atoi(envOr("NEXTENDO_GHOST_IDLE_SECONDS", "")); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return 15 * time.Minute
}

// noteRMC records an RMC call (fed from endpoint.OnRMC): updates the player, the
// global counters, the per-method totals and the live event ring.
func noteRMC(c *nex.Connection, req *nex.RMCMessage) {
	pid := c.PID
	if pid == 0 {
		return
	}
	atomic.AddInt64(&rmcTotal, 1)

	metaMu.Lock()
	now := time.Now()
	pi := playerMeta[pid]
	if pi == nil {
		pi = &playerInfo{PID: pid, FirstSeen: now}
		playerMeta[pid] = pi
		sessionsSeen++
	} else if !pi.LastSeen.IsZero() && now.Sub(pi.LastSeen) > ghostIdle() {
		// Le joueur était dormant (aucune action RMC depuis > seuil fantôme) : on repart sur
		// une NOUVELLE session en ligne. Sans ça, « en ligne depuis » comptait depuis le tout
		// premier paquet du process (des jours) — d'où des « en ligne depuis 100 h » aberrants.
		pi.FirstSeen = now
	}
	pi.LastSeen = now
	pi.Calls++
	pi.LastProto = req.Protocol
	pi.LastMethod = req.Method
	if c.RemoteAddr != "" {
		pi.IP = c.RemoteAddr
	}
	metaMu.Unlock()

	eventsMu.Lock()
	events = append(events, rmcEvent{T: time.Now(), PID: pid, Proto: req.Protocol, Method: req.Method})
	if len(events) > 100 {
		events = events[len(events)-100:]
	}
	methodCount[rmcName(req.Protocol, req.Method)]++
	eventsMu.Unlock()
}

// natTypeLabel turns the NAT mapping+filtering behaviours (ReportNATProperties) into a
// player-facing type for the dashboard.
func natTypeLabel(m, f uint32) string {
	if m == 0 && f == 0 {
		return ""
	}
	if m <= 1 && f <= 1 {
		return "Ouvert"
	}
	if m <= 1 {
		return "Modéré"
	}
	return "Strict"
}

// noteNAT records a player's NAT behaviour + ping. Wired to endpoint.OnNATProperties so the
// monitoring site shows NAT type and latency again (lost when the game moved off the previous stack).
func noteNAT(pid uint64, natMap, natFilter, rtt uint32) {
	if pid == 0 {
		return
	}
	metaMu.Lock()
	defer metaMu.Unlock()
	pi := playerMeta[pid]
	if pi == nil {
		pi = &playerInfo{PID: pid, FirstSeen: time.Now()}
		playerMeta[pid] = pi
	}
	pi.NATMap = natMap
	pi.NATFilter = natFilter
	if rtt > 0 {
		pi.Ping = rtt
	}
}

// ----- GeoIP (best-effort, cached) ------------------------------------------

var (
	geoMu     sync.Mutex
	geoCache  = map[string]geoInfo{}
	geoClient = &http.Client{Timeout: 4 * time.Second}
)

type geoInfo struct {
	Country string `json:"country"`
	CC      string `json:"countryCode"`
	City    string `json:"city"`
	ISP     string `json:"isp"`
}

func ipOnly(addr string) string {
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return addr[:i]
	}
	return addr
}

// geoLookup returns a cached IP geolocation, fetching it once asynchronously (ip-api.com):
// the first call for an IP returns empty and kicks off the fetch, later calls get the result.
func geoLookup(addr string) geoInfo {
	ip := ipOnly(addr)
	geoMu.Lock()
	g, ok := geoCache[ip]
	if !ok {
		geoCache[ip] = geoInfo{} // placeholder so we only fetch once
		geoMu.Unlock()
		go func() {
			var gi geoInfo
			resp, err := geoClient.Get("http://ip-api.com/json/" + ip + "?fields=country,countryCode,city,isp")
			if err == nil {
				defer resp.Body.Close()
				_ = json.NewDecoder(resp.Body).Decode(&gi)
			}
			geoMu.Lock()
			geoCache[ip] = gi
			geoMu.Unlock()
		}()
		return geoInfo{}
	}
	geoMu.Unlock()
	return g
}

// gameModeName maps MK8 online MatchmakeSession game_mode -> a human label.
func gameModeName(mode uint32) string {
	switch mode {
	case 1:
		return "Course"
	case 2:
		return "Course (équipe)"
	case 3:
		return "Bataille"
	case 4:
		return "Bataille (équipe)"
	default:
		return fmt.Sprintf("Mode %d", mode)
	}
}

func rmcName(proto uint16, method uint32) string {
	pn := map[uint16]string{
		0x0A: "TicketGranting", 0x0B: "SecureConnection", 0x6E: "Utility",
		0x70: "Ranking", 0x6D: "MatchmakeExt", 0x15: "MatchMaking",
		0x32: "MatchMakingExt", 0x03: "NATTraversal", 0x0E: "Notifications",
	}[proto]
	if pn == "" {
		pn = fmt.Sprintf("Proto-0x%X", proto)
	}
	mn := ""
	switch proto {
	case 0x0A:
		mn = map[uint32]string{1: "Login", 2: "LoginEx", 3: "RequestTicket"}[method]
	case 0x0B:
		mn = map[uint32]string{1: "Register", 4: "RegisterEx", 7: "ReplaceURL"}[method]
	case 0x6E:
		mn = map[uint32]string{1: "AcquireNexUniqueID", 7: "GetIntegerSettings", 8: "GetStringSettings"}[method]
	case 0x70:
		mn = map[uint32]string{1: "UploadScore", 4: "UploadCommonData", 6: "GetCommonData"}[method]
	case 0x6D:
		mn = map[uint32]string{
			0x26: "CreateMatchmakeSessionWithParam", 0x27: "JoinMatchmakeSessionWithParam",
			0x28: "AutoMatchmakeWithParamPostpone", 0x22: "UpdateProgressScore",
			0x31: "FindMatchmakeSessionBySingleID", 0x3C: "GetSimplePlayingSession",
			0x44: "PrivateRoomCreate", 0x45: "ResolveCode",
		}[method]
	case 0x15:
		mn = map[uint32]string{0x02: "UnregisterGathering", 0x29: "GetSessionURLs", 0x15: "FindBySingleID"}[method]
	case 0x32:
		mn = map[uint32]string{0x01: "EndParticipation"}[method]
	case 0x03:
		mn = map[uint32]string{2: "InitiateProbe", 3: "RequestProbeInitiationExt", 5: "ReportNATProperties"}[method]
	}
	if mn == "" {
		mn = fmt.Sprintf("m%d", method)
	}
	return pn + "::" + mn
}

// ----- stats JSON (keys mirror the proven mk8 dashboard) --------------------

type apiPlayer struct {
	PID        uint64 `json:"pid"`
	Name       string `json:"name"`
	IP         string `json:"ip"`
	State      string `json:"state"`
	Gathering  uint32 `json:"gathering"`
	OnlineSecs int    `json:"onlineSeconds"`
	Calls      int64  `json:"calls"`
	LastAction string `json:"lastAction"`
	IdleSecs   int    `json:"idleSeconds"`
	Country    string `json:"country"`
	CC         string `json:"cc"`
	City       string `json:"city"`
	ISP        string `json:"isp"`
	NatType    string `json:"natType"`
	Ping       int    `json:"ping"`
	VR         uint32 `json:"vr"`
	Mode       string `json:"mode"`
	IsHost     bool   `json:"isHost"`
}

type apiLobbyP struct {
	PID  uint64 `json:"pid"`
	Name string `json:"name"`
	VR   uint32 `json:"vr"`
	Host bool   `json:"host"`
}

type apiGathering struct {
	ID       uint32      `json:"id"`
	HostPID  uint64      `json:"hostPid"`
	HostName string      `json:"hostName"`
	Type     string      `json:"type"`
	Mode     uint32      `json:"mode"`
	VR       uint32      `json:"vr"`
	Players  []apiLobbyP `json:"players"`
	Count    int         `json:"count"`
	Max      uint16      `json:"max"`
	State    string      `json:"state"`
	Code     string      `json:"code,omitempty"`
	Attribs  []uint32    `json:"attribs,omitempty"`
}

type apiEvent struct {
	Ago    int    `json:"agoSeconds"`
	PID    uint64 `json:"pid"`
	Action string `json:"action"`
}

type apiMethod struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

type apiServer struct {
	AccessKey  string `json:"accessKey"`
	NexVersion string `json:"nexVersion"`
	AuthPort   string `json:"authPort"`
	SecurePort int    `json:"securePort"`
	SNIHost    string `json:"sniHost"`
	SessionKey int    `json:"sessionKeyLen"`
	Stack      string `json:"stack"`
}

type apiStats struct {
	ServerTime     string         `json:"serverTime"`
	UptimeSeconds  int            `json:"uptimeSeconds"`
	Connected      int            `json:"connected"`
	InLobby        int            `json:"inLobby"`
	ActiveLobbies  int            `json:"activeLobbies"`
	TotalSessions  int64          `json:"totalSessions"`
	TotalRMC       int64          `json:"totalRmc"`
	GatheringsMade int64          `json:"gatheringsMade"`
	PeakConnected  int            `json:"peakConnected"`
	Server         apiServer      `json:"server"`
	Players        []apiPlayer    `json:"players"`
	Gatherings     []apiGathering `json:"gatherings"`
	Events         []apiEvent     `json:"events"`
	Methods        []apiMethod    `json:"methods"`
}

// dispName : le nom que le joueur a depose dans son profil MK8 (le pseudo en jeu,
// sinon le nom du Mii), lu par le coeur. Sans profil : un nom tire du PID. Un
// profil sans aucun nom lisible le dit, pour qu'on le remarque.
func dispName(pid uint64) string {
	miiName, nickname, ok := nex.CommonDataNamesForPID(pid)
	if !ok {
		return fmt.Sprintf("Joueur-%d", pid%100000)
	}
	if nickname != "" {
		return nickname
	}
	if miiName != "" {
		return miiName
	}
	return fmt.Sprintf("(sans nom) Joueur-%d", pid%100000)
}

func buildStats(endpoint *nex.Endpoint, mm *nex.Matchmaking) apiStats {
	conns := endpoint.SnapshotConnections()
	gaths := mm.Snapshot()

	// Snapshot per-player metadata under the lock.
	type metaSnap struct {
		calls              int64
		first, last        time.Time
		proto              uint16
		meth               uint32
		ip                 string
		natMap, natFilter  uint32
		ping               uint32
	}
	metaMu.Lock()
	snap := make(map[uint64]metaSnap, len(playerMeta))
	for pid, pi := range playerMeta {
		snap[pid] = metaSnap{calls: pi.Calls, first: pi.FirstSeen, last: pi.LastSeen, proto: pi.LastProto, meth: pi.LastMethod, ip: pi.IP,
			natMap: pi.NATMap, natFilter: pi.NATFilter, ping: pi.Ping}
	}
	metaMu.Unlock()

	// Live lobbies -> map each participant to its gathering / mode / vr / host flag.
	pidGathering := map[uint64]uint32{}
	pidMode := map[uint64]uint32{}
	pidVR := map[uint64]uint32{}
	pidIsHost := map[uint64]bool{}
	gs := make([]apiGathering, 0, len(gaths))
	for _, g := range gaths {
		if len(g.Participants) == 0 {
			continue
		}
		max := g.MaxPart
		if max == 0 {
			max = 12
		}
		state := "en recherche"
		if len(g.Participants) >= 2 {
			state = "apparié"
		}
		lps := make([]apiLobbyP, 0, len(g.Participants))
		for _, p := range g.Participants {
			pidGathering[p] = g.ID
			pidMode[p] = g.GameMode
			pidVR[p] = g.VR
			host := p == g.HostPID
			if host {
				pidIsHost[p] = true
			}
			lps = append(lps, apiLobbyP{PID: p, Name: dispName(p), VR: g.VR, Host: host})
		}
		gs = append(gs, apiGathering{
			ID: g.ID, HostPID: g.HostPID, HostName: dispName(g.HostPID),
			Type: gameModeName(g.GameMode), Mode: g.GameMode, VR: g.VR,
			Players: lps, Count: len(g.Participants), Max: max, State: state, Code: g.Code,
			Attribs: g.Attribs,
		})
	}
	sort.Slice(gs, func(i, j int) bool { return gs[i].ID < gs[j].ID })

	// Players from live connections (deduped by PID).
	players := make([]apiPlayer, 0, len(conns))
	inLobby := 0
	seen := map[uint64]bool{}
	for _, c := range conns {
		pid := c.PID
		if pid == 0 || seen[pid] {
			continue
		}
		s := snap[pid]
		// Fantôme : la connexion PRUDP est encore ouverte (le client envoie des PING) mais le
		// joueur n'a fait AUCUNE action RMC depuis > seuil. Ce sont des émulateurs/consoles
		// laissés ouverts qui pinguent pendant des jours ; les compter « en ligne » affichait
		// des « en ligne depuis 100 h » et gonflait le compteur. On les exclut du monitoring
		// (même notion de fantôme que la garde « un seul endroit », cf online_presence.go).
		if s.last.IsZero() || time.Since(s.last) > ghostIdle() {
			continue
		}
		seen[pid] = true
		online := int(time.Since(s.first).Seconds())
		idle := int(time.Since(s.last).Seconds())
		last := rmcName(s.proto, s.meth)
		ip := c.Addr
		if ip == "" {
			ip = s.ip
		}
		gid := pidGathering[pid]
		state := "en ligne"
		if gid != 0 {
			inLobby++
			state = "dans un lobby"
		}
		modeLabel := ""
		if m := pidMode[pid]; m != 0 {
			modeLabel = gameModeName(m)
		}
		geo := geoLookup(ip)
		players = append(players, apiPlayer{
			PID: pid, Name: dispName(pid), IP: ip, State: state, Gathering: gid,
			OnlineSecs: online, Calls: s.calls, LastAction: last, IdleSecs: idle,
			Country: geo.Country, CC: geo.CC, City: geo.City, ISP: geo.ISP,
			NatType: natTypeLabel(s.natMap, s.natFilter), Ping: int(s.ping),
			VR: pidVR[pid], Mode: modeLabel, IsHost: pidIsHost[pid],
		})
	}
	sort.Slice(players, func(i, j int) bool { return players[i].PID < players[j].PID })

	if len(players) > peakConnected {
		peakConnected = len(players)
	}

	// Recent events (newest first) + method totals.
	eventsMu.Lock()
	ev := make([]apiEvent, 0, len(events))
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		ev = append(ev, apiEvent{Ago: int(time.Since(e.T).Seconds()), PID: e.PID, Action: rmcName(e.Proto, e.Method)})
	}
	ms := make([]apiMethod, 0, len(methodCount))
	for n, c := range methodCount {
		ms = append(ms, apiMethod{Name: n, Count: c})
	}
	eventsMu.Unlock()
	sort.Slice(ms, func(i, j int) bool { return ms[i].Count > ms[j].Count })

	return apiStats{
		ServerTime:     time.Now().Format("15:04:05"),
		UptimeSeconds:  int(time.Since(dashStart).Seconds()),
		Connected:      len(players),
		InLobby:        inLobby,
		ActiveLobbies:  len(gs),
		TotalSessions:  atomic.LoadInt64(&sessionsSeen),
		TotalRMC:       atomic.LoadInt64(&rmcTotal),
		GatheringsMade: int64(len(gs)),
		PeakConnected:  peakConnected,
		Server: apiServer{
			AccessKey: accessKey, NexVersion: "4.0.0", AuthPort: fmt.Sprintf("%d", authPort),
			SecurePort: securePort, SNIHost: "g2b309e01-lp1.s.n.srv.nintendo.net", SessionKey: sessionKeyLen,
			Stack: "closed-source (no AGPL)",
		},
		Players:    players,
		Gatherings: gs,
		Events:     ev,
		Methods:    ms,
	}
}

// startDashboard serves the per-game /api/stats JSON, gated by DASH_TOKEN (?key=).
func startDashboard(endpoint *nex.Endpoint, mm *nex.Matchmaking) {
	port := envOr("DASH_PORT", "8082")
	token := envOr("DASH_TOKEN", "")

	// SÉCURITÉ : sans jeton configuré on REFUSE, au lieu d'ouvrir l'API à tout le monde.
	// L'ancienne condition (token == "") laissait la liste des joueurs — pseudos, PID et
	// adresses IP — lisible sans authentification dès que la variable manquait.
	// Comparaison à temps constant : un test == fuit la longueur du préfixe correct.
	authed := func(w http.ResponseWriter, r *http.Request) bool {
		if token != "" && subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("key")), []byte(token)) == 1 {
			return true
		}
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(buildStats(endpoint, mm))
	})
	// /api/kick — libère un compte resté coincé derrière une connexion morte, sans
	// redémarrer le serveur (ce qui déconnecterait tous les joueurs en partie).
	//   ?pid=<PID>     déconnecte toutes les connexions de ce compte
	//   ?rvcid=<id>    déconnecte une connexion précise
	//   (sans param.)  évince immédiatement toutes les connexions mortes
	mux.HandleFunc("/api/kick", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if pid, err := strconv.ParseUint(r.URL.Query().Get("pid"), 10, 64); err == nil && pid != 0 {
			_ = json.NewEncoder(w).Encode(map[string]any{"pid": pid, "kicked": endpoint.KickPID(pid)})
			return
		}
		if rv, err := strconv.ParseUint(r.URL.Query().Get("rvcid"), 10, 32); err == nil && rv != 0 {
			_ = json.NewEncoder(w).Encode(map[string]any{"rvcid": rv, "kicked": endpoint.KickConnection(uint32(rv))})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"reaped": endpoint.ReapIdle(nex.ReapIdleTimeout())})
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })

	fmt.Printf("[MK8 Dashboard] stats API on :%s (token=%v)\n", port, token != "")
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		fmt.Printf("[MK8 Dashboard] HTTP error: %v\n", err)
	}
}
