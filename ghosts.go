package main

// Les fantômes du contre-la-montre, chacun lié au compte Nextendo (PID) de son auteur.
//
// Ce que fait Nintendo (capture du 12/08/2026, tools/switch-capture/CAPTURE-MK8) :
//   - DataStore 24 PreparePostObject : la console annonce un fantôme (108 608 octets) pour un
//     emplacement de persistance = le numéro du circuit (« catégorie ») ; le serveur rend un
//     identifiant et une adresse d'envoi. La console envoie le fichier en POST multipart à
//     https://<adresse> (champs du formulaire + « file »), puis DataStore 26 CompletePostObject.
//   - Ranking 19 UploadScorePack : son temps sur le circuit + la liste de tous ses records
//     (6 octets chacun : temps u32, circuit u16 ; bit 0x40 du circuit = 200cc).
//   - Ranking 9 GetRanking : le classement d'un circuit (profil de chaque joueur = le bloc
//     déposé par Ranking 4, que le cœur garde déjà).
//   - Ranking 20 GetScorePack : pour une liste de PID (les amis), le record de chacun sur un
//     circuit (6 octets, ou vide).
//   - DataStore 25 PrepareGetObject : le fantôme d'un joueur, demandé par (PID, emplacement) ;
//     le serveur rend l'adresse où le lire en HTTPS.
//
// Le fichier ne passe jamais par NEX : on le reçoit et on le sert sur le port TLS du serveur
// secure (60003), par le crochet HTTP du cœur (Server.CustomHTTPHandler).

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	nex "github.com/NextendoNetwork/nextendo-nex"
)

const (
	protocolDataStore uint16 = 0x73

	methodPreparePostObject  = 24
	methodPrepareGetObject   = 25
	methodCompletePostObject = 26

	methodGetRanking      = 9
	methodUploadScorePack = 19
	methodGetScorePack    = 20

	resultDataStoreNotFound = 0x80690004
	ghostMaxSize            = 512 * 1024

	ghostPendingTTL   = time.Hour        // envoi annonce jamais termine : efface ensuite
	ghostReplacedTTL  = 15 * time.Minute // ancien fantome remplace : encore servi (telechargements en cours)
	ghostFlushEvery   = 5 * time.Second
	ghostDefaultQuota = 15 << 30 // place totale des fantomes (le disque de l OVH a 27 Go libres)
)

type ghostObject struct {
	Owner uint64 `json:"owner"`
	Slot  uint16 `json:"slot"`
	Size  uint32 `json:"size"`
	At    int64  `json:"at"`
	Done  bool   `json:"done"`
	Token string `json:"token"`         // secret des adresses d envoi et de lecture (id devinable sinon)
	Old   int64  `json:"old,omitempty"` // remplace par un fantome plus recent (date) : efface apres ghostReplacedTTL
}

type ghostRecord struct {
	Score uint32 `json:"score"`
	At    int64  `json:"at"`
}

type ghostStore struct {
	mu      sync.Mutex
	dir     string
	dirty   bool
	NextID  uint64                            `json:"next_id"`
	Objects map[uint64]*ghostObject           `json:"objects"`
	Slots   map[string]uint64                 `json:"slots"`   // "pid:slot" -> fantôme en place
	Records map[uint64]map[uint16]ghostRecord `json:"records"` // pid -> circuit -> meilleur temps
}

var ghosts = loadGhosts(envOr("NEXTENDO_GHOST_DIR", "/opt/mk8cs/ghosts"))

func loadGhosts(dir string) *ghostStore {
	g := &ghostStore{dir: dir, NextID: 100000, Objects: map[uint64]*ghostObject{}, Slots: map[string]uint64{}, Records: map[uint64]map[uint16]ghostRecord{}}
	_ = os.MkdirAll(dir, 0o755)
	if b, err := os.ReadFile(filepath.Join(dir, "ghosts.json")); err == nil {
		_ = json.Unmarshal(b, g)
		if g.Objects == nil {
			g.Objects = map[uint64]*ghostObject{}
		}
		if g.Slots == nil {
			g.Slots = map[string]uint64{}
		}
		if g.Records == nil {
			g.Records = map[uint64]map[uint16]ghostRecord{}
		}
	}
	fmt.Printf("[MK8 Fantomes] %d fantome(s), %d joueur(s) avec des records, dossier %s\n", len(g.Objects), len(g.Records), dir)
	// les fantomes deposes avant les secrets d adresse (16/10) en recoivent un
	for _, o := range g.Objects {
		if o.Token == "" {
			o.Token = newToken()
			g.dirty = true
		}
	}
	go g.janitor()
	return g
}

// janitor : ecrit l index au plus toutes les 5 s (jamais sur le chemin d une requete : avec des
// milliers de joueurs, le reecrire a chaque record couterait cher), efface les envois jamais
// termines et les fantomes remplaces.
func (g *ghostStore) janitor() {
	t := time.NewTicker(ghostFlushEvery)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		g.mu.Lock()
		for id, o := range g.Objects {
			stale := (!o.Done && now.Sub(time.Unix(o.At, 0)) > ghostPendingTTL) ||
				(o.Old != 0 && now.Sub(time.Unix(o.Old, 0)) > ghostReplacedTTL)
			if stale {
				delete(g.Objects, id)
				_ = os.Remove(g.file(id))
				g.dirty = true
			}
		}
		if g.dirty {
			g.dirty = false
			g.save()
		}
		g.mu.Unlock()
	}
}

func newToken() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// used : la place prise par les fantomes (sous verrou).
func (g *ghostStore) used() (n int64) {
	for _, o := range g.Objects {
		n += int64(o.Size)
	}
	return n
}

// parseKey : « mk8ghost/<id>/<secret> » -> l objet, s il existe et si le secret est le bon.
func (g *ghostStore) parseKey(key string) (uint64, *ghostObject) {
	parts := strings.Split(strings.TrimPrefix(key, "/"), "/")
	if len(parts) != 3 || parts[0] != "mk8ghost" {
		return 0, nil
	}
	id, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return 0, nil
	}
	o := g.Objects[id]
	if o == nil || o.Token == "" || o.Token != parts[2] {
		return 0, nil
	}
	return id, o
}

// save écrit l'index (appelé sous verrou), par fichier temporaire + renommage.
func (g *ghostStore) save() {
	b, err := json.Marshal(g)
	if err != nil {
		return
	}
	tmp := filepath.Join(g.dir, "ghosts.json.tmp")
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, filepath.Join(g.dir, "ghosts.json"))
	}
}

func slotKey(pid uint64, slot uint16) string { return fmt.Sprintf("%d:%d", pid, slot) }

func (g *ghostStore) file(id uint64) string { return filepath.Join(g.dir, fmt.Sprintf("%d.bin", id)) }

// writeFile : par fichier temporaire + renommage, jamais un fantome a moitie ecrit.
func (g *ghostStore) writeFile(id uint64, data []byte) error {
	tmp := g.file(id) + ".part"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, g.file(id))
}

// ghostHost : l'hôte et le port où la console envoie et lit les fantômes (sans « https:// »,
// comme les adresses de Nintendo : la console l'ajoute).
func ghostHost() string {
	return envOr("NEXTENDO_GHOST_HOST", envOr("NEXTENDO_HOST", "127.0.0.1")+":"+envOr("SECURE_PORT", "60003"))
}

// structure NEX : version (0), puis le corps précédé de sa taille.
func structure(s *nex.Settings, body []byte) []byte {
	out := nex.NewStreamOut(s)
	out.U8(0)
	out.Buffer(body)
	return out.Bytes()
}

func keyValue(s *nex.Settings, k, v string) []byte {
	kv := nex.NewStreamOut(s)
	kv.String(k)
	kv.String(v)
	return structure(s, kv.Bytes())
}

// ---------------------------------------------------------------- DataStore

func dataStoreHandler() nex.RMCHandler {
	return func(conn *nex.Connection, req *nex.RMCMessage) *nex.RMCMessage {
		switch req.Method {
		case methodPreparePostObject:
			return preparePostGhost(conn, req)
		case methodCompletePostObject:
			return completePostGhost(conn, req)
		case methodPrepareGetObject:
			return prepareGetGhost(conn, req)
		default:
			fmt.Printf("[NEX] UNHANDLED proto=0x73 method=%d pid=%d callID=%d bodyLen=%d\n", req.Method, conn.PID, req.CallID, len(req.Body))
			return nex.NewRMCError(conn.Settings, protocolDataStore, req.CallID, 0x80010002)
		}
	}
}

// DataStorePreparePostParam : size, name, dataType, metaBinary (qBuffer), permission,
// delPermission, flag, period, referDataId, tags, ratingInitParams, persistenceInitParam
// {slot u16, deleteLastObject bool}, extraData.
func preparePostGhost(conn *nex.Connection, req *nex.RMCMessage) *nex.RMCMessage {
	s := conn.Settings
	in := nex.NewStreamIn(req.Body, s)
	_ = in.U8()
	p := in.Substream()
	size := p.U32()
	_ = p.String()
	_ = p.U16()
	_ = p.QBuffer()
	for i := 0; i < 2; i++ { // permission, delPermission
		_ = p.U8()
		_ = p.Substream()
	}
	_ = p.U32() // flag
	_ = p.U16() // period
	_ = p.U32() // referDataId
	nex.ReadList(p, func(x *nex.StreamIn) string { return x.String() })
	nex.ReadList(p, func(x *nex.StreamIn) []byte { _ = x.U8(); return x.Buffer() })
	_ = p.U8()
	persist := p.Substream()
	slot := persist.U16()
	if p.Err() != nil || size == 0 || size > ghostMaxSize {
		fmt.Printf("[MK8 Fantomes] prepare_post refuse pid=%d size=%d err=%v\n", conn.PID, size, p.Err())
		return nex.NewRMCError(s, protocolDataStore, req.CallID, 0x80690001)
	}

	quota := int64(envOrInt("NEXTENDO_GHOST_QUOTA", ghostDefaultQuota))
	ghosts.mu.Lock()
	if ghosts.used()+int64(size) > quota {
		ghosts.mu.Unlock()
		fmt.Printf("[MK8 Fantomes] prepare_post refuse pid=%d : quota de %d octets atteint\n", conn.PID, quota)
		return nex.NewRMCError(s, protocolDataStore, req.CallID, 0x80690001)
	}
	id := ghosts.NextID
	ghosts.NextID++
	token := newToken()
	ghosts.Objects[id] = &ghostObject{Owner: conn.PID, Slot: slot, Size: size, At: time.Now().Unix(), Token: token}
	ghosts.dirty = true
	ghosts.mu.Unlock()

	body := nex.NewStreamOut(s)
	body.U64(id)
	body.String(ghostHost() + "/")
	body.U32(0) // en-têtes : aucun
	body.U32(1) // champs du formulaire : la clé, que notre réception lit
	body.Write(keyValue(s, "key", fmt.Sprintf("mk8ghost/%d/%s", id, token)))
	body.Buffer(nil) // certificat racine : celui de la console
	fmt.Printf("[MK8 Fantomes] prepare_post pid=%d circuit=%d taille=%d -> id=%d\n", conn.PID, slot, size, id)
	return nex.NewRMCSuccess(s, protocolDataStore, req.Method, req.CallID, structure(s, body.Bytes()))
}

// DataStoreCompletePostParam : dataId u64, isSuccess bool.
func completePostGhost(conn *nex.Connection, req *nex.RMCMessage) *nex.RMCMessage {
	s := conn.Settings
	in := nex.NewStreamIn(req.Body, s)
	_ = in.U8()
	p := in.Substream()
	id := p.U64()
	ok := p.Bool()

	ghosts.mu.Lock()
	o := ghosts.Objects[id]
	if o != nil && o.Owner == conn.PID {
		if _, err := os.Stat(ghosts.file(id)); ok && err == nil && !o.Done {
			o.Done = true
			key := slotKey(o.Owner, o.Slot)
			if old, had := ghosts.Slots[key]; had && old != id {
				if oo := ghosts.Objects[old]; oo != nil {
					oo.Old = time.Now().Unix() // un ami peut etre en train de le telecharger
				}
			}
			ghosts.Slots[key] = id
		} else {
			delete(ghosts.Objects, id)
			_ = os.Remove(ghosts.file(id))
		}
		ghosts.save()
	}
	ghosts.mu.Unlock()
	fmt.Printf("[MK8 Fantomes] complete_post pid=%d id=%d succes=%v\n", conn.PID, id, ok)
	return nex.NewRMCSuccess(s, protocolDataStore, req.Method, req.CallID, nil)
}

// DataStorePrepareGetParam : dataId u64, lockId u32, persistenceTarget {owner u64, slot u16},
// accessPassword u64, extraData. Le fantôme d'un joueur est demandé par (owner, slot).
func prepareGetGhost(conn *nex.Connection, req *nex.RMCMessage) *nex.RMCMessage {
	s := conn.Settings
	in := nex.NewStreamIn(req.Body, s)
	_ = in.U8()
	p := in.Substream()
	id := p.U64()
	_ = p.U32()
	_ = p.U8()
	target := p.Substream()
	owner := target.U64()
	slot := target.U16()

	ghosts.mu.Lock()
	if id == 0 {
		id = ghosts.Slots[slotKey(owner, slot)]
	}
	o := ghosts.Objects[id]
	var size uint32
	var token string
	if o != nil && o.Done {
		size = o.Size
		token = o.Token
	}
	ghosts.mu.Unlock()
	if size == 0 {
		fmt.Printf("[MK8 Fantomes] prepare_get pid=%d owner=%d circuit=%d : aucun fantome\n", conn.PID, owner, slot)
		return nex.NewRMCError(s, protocolDataStore, req.CallID, resultDataStoreNotFound)
	}

	body := nex.NewStreamOut(s)
	body.String(fmt.Sprintf("%s/mk8ghost/%d/%s", ghostHost(), id, token))
	body.U32(0) // en-têtes : aucun
	body.U32(size)
	body.Buffer(nil)
	body.U64(id)
	fmt.Printf("[MK8 Fantomes] prepare_get pid=%d owner=%d circuit=%d -> id=%d (%d octets)\n", conn.PID, owner, slot, id, size)
	return nex.NewRMCSuccess(s, protocolDataStore, req.Method, req.CallID, structure(s, body.Bytes()))
}

// ghostHTTP reçoit (POST multipart « key » + « file ») et sert (GET /mk8ghost/<id>) les
// fantômes, sur le port TLS du serveur secure.
func ghostHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/mk8ghost/"):
		ghosts.mu.Lock()
		id, o := ghosts.parseKey(r.URL.Path)
		done := o != nil && o.Done
		ghosts.mu.Unlock()
		if !done {
			http.NotFound(w, r)
			return
		}
		fmt.Printf("[MK8 Fantomes] lecture id=%d par %s\n", id, r.RemoteAddr)
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, ghosts.file(id))
	case r.Method == http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, ghostMaxSize+64*1024)
		if err := r.ParseMultipartForm(ghostMaxSize + 64*1024); err != nil {
			fmt.Printf("[MK8 Fantomes] envoi illisible de %s : %v\n", r.RemoteAddr, err)
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		key := r.FormValue("key")
		// la console envoie la partie « file » parfois sans nom de fichier : elle est alors
		// dans les valeurs du formulaire et pas dans les fichiers
		var data []byte
		if f, _, ferr := r.FormFile("file"); ferr == nil {
			data, _ = io.ReadAll(io.LimitReader(f, ghostMaxSize+1))
			f.Close()
		} else if v := r.MultipartForm.Value["file"]; len(v) > 0 {
			data = []byte(v[0])
		}
		ghosts.mu.Lock()
		id, o := ghosts.parseKey(key)
		accept := o != nil && !o.Done && len(data) > 0 && len(data) <= ghostMaxSize
		if accept {
			o.Size = uint32(len(data))
		}
		ghosts.mu.Unlock()
		if !accept || ghosts.writeFile(id, data) != nil {
			fmt.Printf("[MK8 Fantomes] envoi refuse id=%d taille=%d\n", id, len(data))
			http.Error(w, "refused", http.StatusForbidden)
			return
		}
		fmt.Printf("[MK8 Fantomes] envoi recu id=%d (%d octets) de %s\n", id, len(data), r.RemoteAddr)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

// ---------------------------------------------------------------- Ranking (temps)

// rankingWithGhosts ajoute au Ranking du cœur les classements du contre-la-montre.
func rankingWithGhosts(base nex.RMCHandler) nex.RMCHandler {
	return func(conn *nex.Connection, req *nex.RMCMessage) *nex.RMCMessage {
		switch req.Method {
		case methodUploadScorePack:
			return uploadScorePack(conn, req)
		case methodGetScorePack:
			return getScorePack(conn, req)
		case methodGetRanking:
			return getRanking(conn, req)
		}
		return base(conn, req)
	}
}

// UploadScorePack : RankingScoreData {category u32, score u32, order u8, updateMode u8,
// groups List<u8>, param u64} puis qBuffer = ses records (temps u32, circuit u16)*.
func uploadScorePack(conn *nex.Connection, req *nex.RMCMessage) *nex.RMCMessage {
	s := conn.Settings
	in := nex.NewStreamIn(req.Body, s)
	_ = in.U8()
	sd := in.Substream()
	category := sd.U32()
	score := sd.U32()
	pack := in.QBuffer()
	now := time.Now().Unix()

	ghosts.mu.Lock()
	rec := ghosts.Records[conn.PID]
	if rec == nil {
		rec = map[uint16]ghostRecord{}
		ghosts.Records[conn.PID] = rec
	}
	keep := func(course uint16, t uint32) {
		if t == 0 {
			return
		}
		if old, ok := rec[course]; !ok || t < old.Score || (t == old.Score && old.At == 0) {
			rec[course] = ghostRecord{Score: t, At: now}
		}
	}
	for i := 0; i+6 <= len(pack); i += 6 {
		keep(uint16(pack[i+4])|uint16(pack[i+5])<<8, uint32(pack[i])|uint32(pack[i+1])<<8|uint32(pack[i+2])<<16|uint32(pack[i+3])<<24)
	}
	if in.Err() == nil {
		keep(uint16(category), score)
	}
	ghosts.dirty = true
	ghosts.mu.Unlock()
	fmt.Printf("[MK8 Fantomes] records pid=%d circuit=%d temps=%d (%d records)\n", conn.PID, category, score, len(pack)/6)
	return nex.NewRMCSuccess(s, nex.ProtocolRanking, req.Method, req.CallID, nil)
}

// GetScorePack : List<PID>, category u32 -> ScorePack {List<qBuffer>} : pour chaque PID,
// son record sur ce circuit (temps u32, circuit u16), ou vide.
func getScorePack(conn *nex.Connection, req *nex.RMCMessage) *nex.RMCMessage {
	s := conn.Settings
	in := nex.NewStreamIn(req.Body, s)
	pids := nex.ReadList(in, func(x *nex.StreamIn) uint64 { return x.PID() })
	category := uint16(in.U32())

	body := nex.NewStreamOut(s)
	body.U32(uint32(len(pids)))
	found := 0
	ghosts.mu.Lock()
	for _, pid := range pids {
		r, ok := ghosts.Records[pid][category]
		if !ok {
			body.QBuffer(nil)
			continue
		}
		found++
		body.QBuffer([]byte{byte(r.Score), byte(r.Score >> 8), byte(r.Score >> 16), byte(r.Score >> 24), byte(category), byte(category >> 8)})
	}
	ghosts.mu.Unlock()
	fmt.Printf("[MK8 Fantomes] records des amis pid=%d circuit=%d : %d/%d\n", conn.PID, category, found, len(pids))
	return nex.NewRMCSuccess(s, nex.ProtocolRanking, req.Method, req.CallID, structure(s, body.Bytes()))
}

type rankedTime struct {
	pid   uint64
	score uint32
	at    int64
}

// nexTime : la date au format compressé de NEX (seconde, minute, heure, jour, mois, année).
func nexTime(t time.Time) uint64 {
	t = t.UTC()
	return uint64(t.Second()) | uint64(t.Minute())<<6 | uint64(t.Hour())<<12 | uint64(t.Day())<<17 | uint64(t.Month())<<22 | uint64(t.Year())<<26
}

// GetRanking : mode u8 (0 = en tête, 1 = autour du joueur), category u32, RankingOrderParam
// {orderCalc u8, groupIndex u8, groupNum u8, timeScope u8, offset u32, count u8}, uniqueId u64,
// pid u64 -> RankingResult {List<RankingRankData>, total u32, sinceTime DateTime}.
func getRanking(conn *nex.Connection, req *nex.RMCMessage) *nex.RMCMessage {
	s := conn.Settings
	in := nex.NewStreamIn(req.Body, s)
	mode := in.U8()
	category := in.U32()
	_ = in.U8()
	order := in.Substream()
	_ = order.U8()
	_ = order.U8()
	_ = order.U8()
	_ = order.U8()
	offset := int(order.U32())
	count := int(order.U8())
	_ = in.U64()
	pid := in.PID()
	if pid == 0 {
		pid = conn.PID
	}
	if count <= 0 || count > 100 {
		count = 10
	}

	var list []rankedTime
	ghosts.mu.Lock()
	for p, rec := range ghosts.Records {
		if r, ok := rec[uint16(category)]; ok {
			list = append(list, rankedTime{p, r.Score, r.At})
		}
	}
	ghosts.mu.Unlock()
	sort.Slice(list, func(i, j int) bool {
		if list[i].score != list[j].score {
			return list[i].score < list[j].score
		}
		return list[i].at < list[j].at
	})

	start := offset
	if mode == 1 {
		start = 0
		for i, e := range list {
			if e.pid == pid {
				start = i - count/2
				break
			}
		}
	}
	if start < 0 {
		start = 0
	}
	end := start + count
	if end > len(list) {
		end = len(list)
	}
	if start > end {
		start = end
	}

	body := nex.NewStreamOut(s)
	body.U32(uint32(end - start))
	for i := start; i < end; i++ {
		e := list[i]
		d := nex.NewStreamOut(s)
		d.PID(e.pid)
		d.U64(0)             // uniqueId
		d.U32(uint32(i + 1)) // rang
		d.U32(category)
		d.U32(e.score)
		d.U32(2) // groupes, comme Nintendo
		d.U8(0)
		d.U8(0)
		d.U64(0) // param
		d.Buffer(nex.CommonData(e.pid))
		d.U64(nexTime(time.Unix(e.at, 0)))
		body.Write(structure(s, d.Bytes()))
	}
	body.U32(uint32(len(list)))
	body.U64(nexTime(time.Now()))
	fmt.Printf("[MK8 Fantomes] classement pid=%d circuit=%d mode=%d : %d-%d sur %d\n", conn.PID, category, mode, start+1, end, len(list))
	return nex.NewRMCSuccess(s, nex.ProtocolRanking, req.Method, req.CallID, structure(s, body.Bytes()))
}
