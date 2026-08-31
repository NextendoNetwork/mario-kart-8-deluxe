package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	nex "github.com/NextendoNetwork/nextendo-nex"
)

// Interrupteur du relais P2P de Mario Kart 8.
//
// Le relais lui-meme vit dans le coeur (relaypair.go) : un port UDP par PAIRE de joueurs,
// ouvert a la demande, qui fait traverser tout ce qui arrive sans lire un octet. Ici il n y
// a que l armement.
//
// L etat tient dans un FICHIER, dont le contenu est l adresse publique a annoncer :
// "<ip>" ou "<ip>:<portDeBase>". Fichier absent ou vide = relais eteint.
//
// Ni variable d environnement, ni adresse en dur : une variable imposerait de RECREER le
// conteneur a chaque essai, donc de reconstruire sa configuration a la main et de
// deconnecter tous les joueurs a chaque fois. Un fichier s ecrit et s efface a chaud, et le
// retour arriere tient en un rm — ce qui compte pour un reglage qui touche le chemin P2P du
// jeu le plus frequente.
var (
	relayFlagPath = relayStrEnv("MK8_RELAY_FILE", "/nat/relay_on_mk8")
	relayPortBase = relayIntEnv("MK8_RELAY_PORT_BASE", 31100)
	relayPortSpan = relayIntEnv("MK8_RELAY_PORT_SPAN", 900)

	relayMu      sync.Mutex
	relayHostCur string
	relayChecked time.Time
)

func relayStrEnv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}

	return d
}

func relayIntEnv(k string, d int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}

	return d
}

// startRelayWatcher relit le fichier toutes les deux secondes et tient le coeur en phase.
// Une boucle plutot qu une lecture a la demande : ainsi l armement se voit dans le journal
// immediatement, sans attendre qu un joueur rejoigne — sinon un essai est illisible.
func startRelayWatcher() {
	go func() {
		for {
			relayRelire()
			time.Sleep(2 * time.Second)
		}
	}()
}

func relayRelire() {
	relayMu.Lock()
	defer relayMu.Unlock()

	if time.Since(relayChecked) < time.Second {
		return
	}
	relayChecked = time.Now()

	host, base := "", relayPortBase
	if b, err := os.ReadFile(relayFlagPath); err == nil {
		champ := strings.TrimSpace(string(b))
		if i := strings.IndexAny(champ, "\r\n"); i >= 0 {
			champ = strings.TrimSpace(champ[:i])
		}
		if champ != "" {
			if h, p, err := net.SplitHostPort(champ); err == nil {
				if n, err := strconv.Atoi(p); err == nil && n > 0 {
					host, base = h, n
				}
			} else {
				host = champ
			}
		}
		// Une adresse illisible vaut relais eteint : mieux vaut le comportement d hier que
		// des stations pointant sur une adresse que personne ne peut joindre.
		if host != "" && net.ParseIP(host) == nil {
			fmt.Printf("[MK8 relais] %s: %q n est pas une adresse IP — relais laisse eteint\n", relayFlagPath, host)
			host = ""
		}
	}

	if host == relayHostCur {
		return
	}
	relayHostCur = host

	if host != "" {
		fmt.Printf("[MK8 relais] ARME — un port par paire sur %s:%d-%d\n", host, base, base+relayPortSpan-1)
		nex.SetPairRelay(host, base, relayPortSpan)
	} else {
		fmt.Printf("[MK8 relais] ETEINT — retour au pont NAT direct\n")
		nex.SetPairRelay("", 0, 0)
	}
}
