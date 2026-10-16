package main

import (
	"bytes"
	"encoding/hex"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	nex "github.com/NextendoNetwork/nextendo-nex"
)

// Trames du vrai serveur de Nintendo (capture du 12/08/2026), PID des joueurs remplaces.
const (
	capPreparePost = "005600000040a8010001000000000000000500000000000000000005000000030000000000000000010000000000000000000000000000030000000b0001060000000800556e6b6e6f776e00010000010000010000010000010000"
	capPrepareGet  = "0040000000000000000000000000000000000a00000008070605040302010b000000000000000000060000000800556e6b6e6f776e00010000010000010000010000010000"
	capScorePack   = "001a0000000b0000005fb501000001040000000000000000000000000000008a0078cd010000002f400100400059ea01000100c95a01004100ff2e02000200548d01004200c0ee0100030053ec01000400ad7a01004400bd15020005002f89010045005fb501000b00a53a01004b0099ba01000c00594001004c00867501001100ab0a0100510066d201001400ac7b01001600670f010056002a6f01001900c61c02001a005d9501005a00"
	capGetRanking  = "000b000000000900000000ff0002000000000a00000000000000000000000000000000"
)

func unhex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGhostRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ghosts = loadGhosts(dir)
	s := nex.NewSwitchSettings("00000000", 40600)
	me := &nex.Connection{Settings: s, PID: 0x0102030405060708}

	// envoi annoncé : circuit 11, 108 608 octets
	resp := preparePostGhost(me, &nex.RMCMessage{Method: methodPreparePostObject, CallID: 1, Body: unhex(t, capPreparePost)})
	if len(ghosts.Objects) != 1 {
		t.Fatalf("prepare_post : %d objet(s)", len(ghosts.Objects))
	}
	var id uint64
	for k, o := range ghosts.Objects {
		id = k
		if o.Slot != 11 || o.Size != 108608 || o.Owner != me.PID {
			t.Fatalf("prepare_post lu de travers : %+v", o)
		}
	}
	_ = resp

	// le fichier, comme la console l'envoie (partie « file » sans nom de fichier)
	var form bytes.Buffer
	w := multipart.NewWriter(&form)
	_ = w.WriteField("key", "mk8ghost/"+itoa(id)+"/"+ghosts.Objects[id].Token)
	_ = w.WriteField("file", string(bytes.Repeat([]byte{7}, 108608)))
	w.Close()
	req := httptest.NewRequest(http.MethodPost, "/", &form)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()
	ghostHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("envoi : %d %s", rec.Code, rec.Body.String())
	}

	// fin d'envoi
	done := nex.NewStreamOut(s)
	done.U8(0)
	inner := nex.NewStreamOut(s)
	inner.U64(id)
	inner.Bool(true)
	done.Buffer(inner.Bytes())
	completePostGhost(me, &nex.RMCMessage{Method: methodCompletePostObject, CallID: 2, Body: done.Bytes()})
	if !ghosts.Objects[id].Done {
		t.Fatal("fantome non valide apres complete_post")
	}

	// un ami le demande par (PID, circuit), exactement comme la capture
	friend := &nex.Connection{Settings: s, PID: 42}
	got := prepareGetGhost(friend, &nex.RMCMessage{Method: methodPrepareGetObject, CallID: 3, Body: unhex(t, capPrepareGet)})
	if got == nil || len(got.Body) == 0 {
		t.Fatal("prepare_get : pas de reponse")
	}

	// et le lit
	rec = httptest.NewRecorder()
	ghostHTTP(rec, httptest.NewRequest(http.MethodGet, "/mk8ghost/"+itoa(id)+"/"+ghosts.Objects[id].Token, nil))
	if rec.Code != http.StatusOK || rec.Body.Len() != 108608 {
		t.Fatalf("lecture : %d, %d octets", rec.Code, rec.Body.Len())
	}

	// ses records (capture : circuit 11 en 111967 ms, 23 records)
	uploadScorePack(me, &nex.RMCMessage{Method: methodUploadScorePack, CallID: 4, Body: unhex(t, capScorePack)})
	if r := ghosts.Records[me.PID][11]; r.Score != 111967 {
		t.Fatalf("record du circuit 11 : %d", r.Score)
	}
	if len(ghosts.Records[me.PID]) != 23 {
		t.Fatalf("%d records au lieu de 23", len(ghosts.Records[me.PID]))
	}
	if ghosts.Objects[id].Score != 111967 {
		t.Fatalf("temps du fantome : %d", ghosts.Objects[id].Score)
	}

	// un circuit de la liste de records (0x40) sans fantome envoye : ni classement, ni record
	// d ami, sinon le jeu demande un fantome introuvable (2306-1204)
	other := nex.NewStreamOut(s)
	other.U8(0)
	other.U32(0x40)
	other.U8(0)
	ord := nex.NewStreamOut(s)
	ord.U8(0)
	ord.U8(0xff)
	ord.U8(0)
	ord.U8(2)
	ord.U32(0)
	ord.U8(10)
	other.Buffer(ord.Bytes())
	other.U64(0)
	other.U64(0)
	empty := getRanking(friend, &nex.RMCMessage{Method: methodGetRanking, CallID: 9, Body: other.Bytes()})
	ein := nex.NewStreamIn(empty.Body, s)
	_ = ein.U8()
	if n := ein.Substream().U32(); n != 0 {
		t.Fatalf("classement d un circuit sans fantome : %d entree(s)", n)
	}

	// le classement du circuit 11, demandé comme la capture
	rk := getRanking(friend, &nex.RMCMessage{Method: methodGetRanking, CallID: 5, Body: unhex(t, capGetRanking)})
	in := nex.NewStreamIn(rk.Body, s)
	_ = in.U8()
	res := in.Substream()
	if n := res.U32(); n != 1 {
		t.Fatalf("classement : %d entree(s)", n)
	}
	_ = res.U8()
	entry := res.Substream()
	if pid := entry.PID(); pid != me.PID {
		t.Fatalf("classement : pid %x", pid)
	}

	// les records des amis : la liste de la capture contient ce joueur en 2e position
	sp := nex.NewStreamOut(s)
	sp.U32(2)
	sp.U64(0x1111111111111111)
	sp.U64(me.PID)
	sp.U32(11)
	pack := getScorePack(friend, &nex.RMCMessage{Method: methodGetScorePack, CallID: 6, Body: sp.Bytes()})
	want := "00" + "0e000000" + "02000000" + "0000" + "0600" + "5fb501000b00"
	if hex.EncodeToString(pack.Body[len(pack.Body)-len(want)/2:]) != want {
		t.Fatalf("score pack : %x", pack.Body)
	}

	// sans le secret : refusé (ni lecture, ni envoi dans le fantôme d'un autre)
	rec = httptest.NewRecorder()
	ghostHTTP(rec, httptest.NewRequest(http.MethodGet, "/mk8ghost/"+itoa(id)+"/0000", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("lecture sans secret : %d", rec.Code)
	}

	// l'index survit à un redémarrage
	ghosts.mu.Lock()
	ghosts.save()
	ghosts.mu.Unlock()
	again := loadGhosts(dir)
	if again.Slots[slotKey(me.PID, 11)] != id {
		t.Fatal("index non relu")
	}
	_ = os.Remove(dir)
}

func itoa(v uint64) string { return string(strconvAppend(nil, v)) }

func strconvAppend(b []byte, v uint64) []byte {
	if v >= 10 {
		b = strconvAppend(b, v/10)
	}
	return append(b, byte('0'+v%10))
}
