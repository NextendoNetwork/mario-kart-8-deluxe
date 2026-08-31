package main

// La liste des joueurs autorises a passer par le relais.
//
// Le coeur decide qui en a BESOIN ; ce fichier decide qui y a DROIT. La distinction existe
// parce que la mesure du besoin s est trompee trois fois de suite le 2026-08-30 : a chaque
// essai, des joueurs qui se joignaient tres bien se sont retrouves dehors.
//
// Fichier plutot que variable d environnement, pour la meme raison que relay_on : une
// variable imposerait de RECREER le conteneur a chaque changement, donc de deconnecter tout
// le monde — precisement ce qu on cherche a eviter en n exposant que quelques volontaires.
//
// Format, un jeton par ligne :
//
//	1800000123     autorise
//	!1800000123    autorise ET force (relaye sans attendre qu il echoue)
//	TOUS           elargit a tous ceux qui en ont besoin — pas pendant une validation
//	# ...          commentaire
//
// Fichier absent, vide ou illisible : PERSONNE n est relaye, meme relais arme.

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	nex "github.com/NextendoNetwork/nextendo-nex"
)

var (
	listePath = relayStrEnv("MK8_RELAY_ALLOW", "/nat/relay_allow_mk8")

	listeMu      sync.Mutex
	listeSignatu string
)

// parseVolontaires lit le format ci-dessus. Extrait de la lecture du fichier pour etre
// testable sans disque. Une ligne malformee est IGNOREE et jamais prise pour un joker.
func parseVolontaires(r *bufio.Scanner) (pids, forces []uint64, ouvert bool) {
	for r.Scan() {
		champ := strings.TrimSpace(r.Text())
		if i := strings.Index(champ, "#"); i >= 0 {
			champ = strings.TrimSpace(champ[:i])
		}
		if champ == "" {
			continue
		}
		if strings.EqualFold(champ, "TOUS") {
			ouvert = true

			continue
		}
		force := strings.HasPrefix(champ, "!")
		champ = strings.TrimPrefix(champ, "!")

		n, err := strconv.ParseUint(champ, 10, 64)
		if err != nil || n == 0 {
			fmt.Printf("[MK8 relais] liste: ligne ignoree %q\n", champ)

			continue
		}
		pids = append(pids, n)
		if force {
			forces = append(forces, n)
		}
	}

	return pids, forces, ouvert
}

// listeRelire recharge la liste et ne journalise QUE si elle a change : a deux secondes
// d intervalle, une ligne par passage rendrait le journal illisible pendant un essai.
func listeRelire() {
	listeMu.Lock()
	defer listeMu.Unlock()

	var pids, forces []uint64
	var ouvert bool

	f, err := os.Open(listePath)
	if err == nil {
		pids, forces, ouvert = parseVolontaires(bufio.NewScanner(f))
		f.Close()
	}
	// err != nil (fichier absent ou illisible) laisse les listes vides : le relais se ferme.

	sig := fmt.Sprintf("%v|%v|%v", pids, forces, ouvert)
	if sig == listeSignatu {
		return
	}
	listeSignatu = sig

	nex.SetRelayVolontaires(pids, forces, ouvert)

	switch {
	case ouvert:
		fmt.Printf("[MK8 relais] liste ELARGIE A TOUS (%d nommes) — le relais peut toucher n importe qui\n", len(pids))
	case len(pids) == 0:
		fmt.Printf("[MK8 relais] liste vide — le relais est ferme a tout le monde\n")
	default:
		fmt.Printf("[MK8 relais] volontaires: %d %v (forces: %v)\n", len(pids), pids, forces)
	}
}

// startListeWatcher relit la liste au meme rythme que l interrupteur.
func startListeWatcher() {
	go func() {
		tour := 0
		for {
			// Les ajouts automatiques sont evalues moins souvent que la relecture : le
			// critere porte sur des dizaines de tentatives, il ne bouge pas en deux
			// secondes, et reecrire le fichier a ce rythme serait absurde.
			if tour%30 == 0 {
				listeAutoEcrire()
			}
			listeRelire()
			tour++
			time.Sleep(2 * time.Second)
		}
	}()
}

// --- ajouts automatiques ---------------------------------------------------
//
// Un joueur qui arrive demain et n arrive jamais a se connecter ne doit pas rester dehors
// parce que la liste a ete ecrite hier. Le serveur ajoute donc lui-meme ceux qui remplissent
// un critere DUR : au moins dix percages directs tentes, aucun reussi. Ceux-la ne peuvent
// rien perdre — ils ne jouent pas.
//
// Le fichier reste modifiable a la main : les lignes ecrites par le serveur vivent entre deux
// marqueurs, et tout ce qui est en dehors est recopie tel quel. Ce qui est ajoute
// automatiquement est REGENERE a chaque passage, donc un joueur qui se met a se connecter en
// sort tout seul.

const (
	marqueurDebut = "# --- ajouts automatiques (ne pas editer sous cette ligne) ---"
	marqueurFin   = "# --- fin des ajouts automatiques ---"
)

// listeAutoEcrire regenere la section automatique du fichier. Ne touche jamais aux lignes
// manuelles, et n ecrit rien si le contenu ne change pas — le fichier est relu toutes les
// deux secondes et une reecriture inutile ferait battre le journal.
func listeAutoEcrire() {
	candidats := nex.CandidatsRelais()

	manuel := []string{}
	if b, err := os.ReadFile(listePath); err == nil {
		dedans := false
		for _, l := range strings.Split(string(b), "\n") {
			switch {
			case strings.HasPrefix(l, marqueurDebut):
				dedans = true
			case strings.HasPrefix(l, marqueurFin):
				dedans = false
			case !dedans:
				manuel = append(manuel, l)
			}
		}
	}
	for len(manuel) > 0 && strings.TrimSpace(manuel[len(manuel)-1]) == "" {
		manuel = manuel[:len(manuel)-1]
	}

	var b strings.Builder
	for _, l := range manuel {
		b.WriteString(l)
		b.WriteString("\n")
	}
	if len(candidats) > 0 {
		b.WriteString("\n")
		b.WriteString(marqueurDebut)
		b.WriteString("\n")
		for _, p := range candidats {
			fmt.Fprintf(&b, "%d\n", p)
		}
		b.WriteString(marqueurFin)
		b.WriteString("\n")
	}

	nouveau := b.String()
	if ancien, err := os.ReadFile(listePath); err == nil && string(ancien) == nouveau {
		return
	}
	// Ecriture atomique : le vigilant relit toutes les deux secondes et ne doit jamais
	// tomber sur un fichier a moitie ecrit, ce qui le fermerait pour rien.
	tmp := listePath + ".tmp"
	if err := os.WriteFile(tmp, []byte(nouveau), 0o644); err != nil {
		fmt.Printf("[MK8 relais] liste: ecriture impossible: %v\n", err)

		return
	}
	if err := os.Rename(tmp, listePath); err != nil {
		fmt.Printf("[MK8 relais] liste: remplacement impossible: %v\n", err)

		return
	}
	fmt.Printf("[MK8 relais] liste: %d ajout(s) automatique(s) — joueurs sans aucune connexion reussie\n", len(candidats))
}
