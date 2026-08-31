// Command mk8 runs the Mario Kart 8 Deluxe online servers (auth + secure) on the
// Nextendo NEX stack — our own closed-source NEX implementation, with no third-party
// AGPL code. It is the transition target for closing the public
// servers built on the previous stack.
//
// Two NEX servers run in one process:
//   - auth   (:443)   TicketGranting — LoginEx issues the Kerberos ticket.
//   - secure (:60003) SecureConnection + matchmaking + NAT-traversal + ranking + utility.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"os"
	"strconv"
	"strings"
	"time"

	nex "github.com/NextendoNetwork/nextendo-nex"
)

const (
	accessKey      = "09c1c475"
	nexVersion     = 40000
	securePID      = 2
	securePassword = "securepasswordplz1"
	sessionKeyLen  = 32
)

var (
	nextendoHost = envOr("NEXTENDO_HOST", "127.0.0.1")
	authPort     = envOrInt("AUTH_PORT", 443)
	securePort   = envOrInt("SECURE_PORT", 60003)
	certFile     = envOr("CERT_FILE", `C:\Dev\Dev\reverse eden\server\certs\local_server_cert.pem`)
	keyFile      = envOr("KEY_FILE", `C:\Dev\Dev\reverse eden\server\certs\local_server_key.pem`)

	// nextendoSecret signs "nx2." NEX login tokens issued by the account service. It
	// MUST be byte-identical to nextendo-account's secret or token validation fails.
	// Match its loadSecret exactly: env NEXTENDO_SECRET as raw bytes, else hex-decode
	// the shared key file (the account has no env → it hex-decodes nextendo_secret.key).
	nextendoSecret = loadNextendoSecret()
	// requireAccount, when "1", rejects any login without a valid Nextendo token,
	// keeping the closed-source test server private to account holders.
	requireAccount = os.Getenv("NEXTENDO_REQUIRE_ACCOUNT") == "1"
)

func main() {
	settings := nex.NewSwitchSettings(accessKey, nexVersion)

	// --- Auth server (insecure, :443) ---
	secureURL := nex.NewStationURL("prudp")
	secureURL.Set("address", nextendoHost)
	secureURL.SetInt("port", securePort)
	secureURL.SetInt("CID", 1)
	secureURL.SetInt("PID", securePID)
	secureURL.SetInt("sid", 1)
	secureURL.SetInt("stream", 10)
	secureURL.SetInt("type", 2) // public

	authEndpoint := nex.NewEndpoint(settings)
	authCfg := &nex.AuthConfig{
		Settings:         settings,
		SecurePID:        securePID,
		SecurePassword:   securePassword,
		SecureStationURL: secureURL,
		ServerName:       "Nextendo",
		SessionKeyLength: sessionKeyLen,
		ResolveUser:      resolveUser,
	}
	authEndpoint.Register(nex.ProtocolTicketGranting, authCfg.Handler())
	authEndpoint.OnRMC = logRMC("Auth")
	authServer := nex.NewServer(authEndpoint)

	// --- Secure server (:60003) ---
	secureEndpoint := nex.NewEndpoint(settings)
	secureEndpoint.SetSecureAccount(securePassword, securePID)

	mm := nex.NewMatchmaking()
	secureEndpoint.Register(nex.ProtocolSecureConnection, nex.SecureConnectionHandler())
	secureEndpoint.Register(nex.ProtocolMatchmakeExtension, mm.ExtensionHandler())
	secureEndpoint.Register(nex.ProtocolMatchMaking, mm.MatchMakingHandler())
	secureEndpoint.Register(nex.ProtocolMatchMakingExt, mm.MatchMakingExtHandler())
	secureEndpoint.Register(nex.ProtocolNATTraversal, nex.NATTraversalHandler())
	secureEndpoint.Register(nex.ProtocolRanking, nex.RankingHandler())
	secureEndpoint.Register(nex.ProtocolUtility, nex.UtilityHandler())
	logSecure := logRMC("Secure")
	secureEndpoint.OnRMC = func(c *nex.Connection, req *nex.RMCMessage) {
		logSecure(c, req)
		noteRMC(c, req) // feed the monitoring dashboard
	}
	secureEndpoint.OnNATProperties = noteNAT // dashboard: NAT type + ping from ReportNATProperties
	secureEndpoint.OnConnect = func(c *nex.Connection) {
		fmt.Printf("[MK8 Secure] connected pid=%d id=%d addr=%s\n", c.PID, c.ID, c.RemoteAddr)
	}
	// Drop the player's lobbies when the connection dies. A gathering is otherwise only
	// removed when the client politely calls UnregisterGathering / EndParticipation, so a
	// client that crashes or errors out leaks its lobby forever: the monitoring fills with
	// phantom lobbies "searching" for a player who is long gone, and matchmaking can hand
	// those dead sessions to real players.
	secureEndpoint.OnDisconnect = func(c *nex.Connection) {
		mm.RemovePlayer(c.PID)
	}
	secureServer := nex.NewServer(secureEndpoint)

	// Monitoring: per-game /api/stats for the unified Nextendo dashboard.
	// Éviction automatique des connexions mortes. Sans elle, une session perdue (crash,
	// coupure, émulateur fermé) restait enregistrée indéfiniment : le joueur se voyait
	// refuser l'accès (« ce compte joue déjà ailleurs ») et les compteurs étaient faux.
	secureEndpoint.StartReaper()
	go startDashboard(secureEndpoint, mm)

	// Relais de station. Le port UDP ecoute toujours ; la SUBSTITUTION est armee par le
	// fichier interrupteur (/nat/relay_on_mk8), et la liste des autorises par
	// /nat/relay_allow_mk8. Sans liste, PERSONNE n est relaye, meme arme : c est la regle
	// qui a manque le 2026-08-30, ou trois essais de suite ont touche des joueurs qui
	// n avaient rien demande.
	startRelayWatcher()
	startListeWatcher()

	// When the auth is fronted by a TLS-passthrough proxy (Traefik on the shared :443),
	// enable PROXY protocol so the auth sees the console's REAL IP. Without it the login PID is
	// remembered under Traefik's internal IP (10.0.1.x), and MK8's TICKETLESS secure CONNECT —
	// which arrives on the host-published :60003 with the real client IP — can't RecallAuthPID it,
	// falling back to an incrementing placeholder PID (1800000001, 1800000002, ...) the console
	// doesn't recognise as itself -> Pia self-recognition fails -> SessionKeepFailed / comm error.
	proxyProto := os.Getenv("NEXTENDO_PROXY_PROTOCOL") == "1"
	go func() {
		fmt.Printf("[MK8 Auth] listening WSS :%d (proxyProto=%v, secure URL -> %s)\n", authPort, proxyProto, secureURL.String())
		var err error
		if proxyProto {
			err = authServer.ListenSecureProxy(authPort, certFile, keyFile)
		} else {
			err = authServer.ListenSecure(authPort, certFile, keyFile)
		}
		if err != nil {
			fmt.Printf("[MK8 Auth] stopped: %v\n", err)
		}
	}()

	fmt.Printf("[MK8 Secure] listening WSS :%d\n", securePort)
	if err := secureServer.ListenSecure(securePort, certFile, keyFile); err != nil {
		fmt.Printf("[MK8 Secure] stopped: %v\n", err)
	}
}

// resolveUser maps a LoginEx username to an account. A valid "nx2." Nextendo
// token resolves to its persistent PID; anything else gets a stable anonymous
// PID derived from the username (so the same console keeps the same identity).
func resolveUser(username string, extraData []byte) (uint64, []byte, bool) {
	// The source key encrypts the client ticket and is handed back as pSourceKey,
	// so the console decrypts it. It MUST be 32 bytes (the Switch kerberos key
	// size) — a 16-byte key makes the console reject the ticket. Derive it
	// deterministically per user.
	sk := sha256.Sum256([]byte("nextendo-src:" + username))
	sourceKey := sk[:]

	// 1. Signed nx2 token → the account's PERSISTENT PID (+ online gates).
	if pid, ok := nextendoPIDFromToken(username); ok {
		if allow, reason := nextendoOnlineCheck(pid, "ryujinx"); !allow {
			fmt.Printf("[Auth] pid=%d online REFUSÉ (%s)\n", pid, reason)
			return 0, nil, false
		}
		return pid, sourceKey, true
	}

	// 2. Numeric username. The emulator's "Connexion Nextendo" button sends the
	// account's OWN PID (a bare number in the Nextendo range) as the username; a REAL
	// CFW Switch sends its console baasUserID (a large NSA id) instead, which we must
	// resolve to the account PID. Using the account PID verbatim keeps the NEX identity
	// = the account the game knows itself by (hashing it breaks Pia's self-recognition
	// → 2618-562 SessionKeepFailed).
	if n, err := strconv.ParseUint(username, 10, 64); err == nil && n >= 1800000000 {
		// Le jeu envoie un PID NU comme identité (aucune signature). Les PID étant
		// séquentiels depuis 1800000001, envoyer le numéro d'un autre membre suffirait à
		// jouer sous son identité — et, via la garde « un seul endroit », à l'empêcher
		// lui-même de jouer. On referme la faille en EXIGEANT la preuve cryptographique
		// que l'émulateur (>= 1.7.1) glisse dans l'extraData du login : le jeton nx2 signé
		// (HMAC au secret serveur) porté par le claim "nnex" du id_token BAAS. On valide ce
		// jeton et on exige qu'il prouve EXACTEMENT le PID annoncé.
		provenPID, proven := uint64(0), false
		if tok, ok := nex.NexTokenFromLoginExtraData(extraData); ok {
			provenPID, proven = nextendoPIDFromToken(tok)
		}
		// L'enforce ne cible que la plage émulateur (username = le PID du compte lui-même).
		// Une vraie Switch (NSA >= 1810000000) n'envoie pas de jeton nx2 ; elle reste sur
		// resolveNSAtoPID pour ne pas casser les consoles CFW légitimes.
		if n < 1810000000 {
			switch {
			case proven && provenPID == n:
				fmt.Printf("[Auth][bind] pid=%d OK : le nx2 prouve le PID\n", n)
			case proven && provenPID != n:
				fmt.Printf("[Auth][bind] pid=%d USURPATION : le nx2 prouve %d, pas %d\n", n, provenPID, n)
			default:
				fmt.Printf("[Auth][bind] pid=%d SANS PREUVE : aucun nx2 dans l'extraData (build < 1.7.1 ?)\n", n)
			}
			if requireSignedToken() && !(proven && provenPID == n) {
				fmt.Printf("[Auth] pid=%d REFUSÉ : identité non prouvée (jeton nx2 signé requis)\n", n)
				return 0, nil, false
			}
		}
		pid, kind := n, "ryujinx"
		if n >= 1810000000 { // vraie Switch : NSA id -> PID de compte (online = comptes Nextendo UNIQUEMENT)
			kind = "switch"
			rp, st := resolveNSAtoPID(n)
			switch st {
			case nsaOK:
				pid = rp
				fmt.Printf("[Auth] NSA %d -> account pid=%d\n", n, pid)
			case nsaUnknown:
				fmt.Printf("[Auth] NSA %d REFUSÉ (aucun compte Nextendo)\n", n)
				return 0, nil, false
			case nsaUnreachable:
				fmt.Printf("[Auth] NSA %d REFUSÉ (serveur compte injoignable)\n", n)
				return 0, nil, false
			}
		}
		// GATES online : #6 e-mail vérifié + #5 un seul endroit + compte inconnu/désactivé.
		if allow, reason := nextendoOnlineCheck(pid, kind); !allow {
			fmt.Printf("[Auth] pid=%d online REFUSÉ (%s)\n", pid, reason)
			return 0, nil, false
		}
		return pid, sourceKey, true
	}

	// 3. Anonymous / no Nextendo identity. When requireAccount is on, online REQUIRES
	// a Nextendo account → reject (the game can't enter online mode).
	if requireAccount {
		fmt.Printf("[Auth] login anonyme REFUSÉ (compte Nextendo requis): %q\n", username)
		return 0, nil, false
	}
	return anonymousPID(username), sourceKey, true
}

// revokedNexPayloads liste les charges utiles de nex_token fuités ("pid.username.expiry") qui
// DOIVENT être refusées bien que leur signature HMAC soit valide. Incident 2026-07-22 : la
// release 1.6.5 Windows a été empaquetée depuis un dossier où le mainteneur s'était connecté,
// donc portable/nextendo_account.txt (une session vivante) a été livré à chaque téléchargeur —
// fuite de ce jeton exact vers toute la communauté. Le denylist tue le jeton partout où il est
// présenté, sans faire tourner le secret partagé (ce qui déconnecterait tout le monde). À garder
// synchronisé avec la liste identique dans nextendo-account et les autres serveurs de jeu.
var revokedNexPayloads = map[string]bool{
	"1800000006.Kazuu.1787343209": true, // fuite release 1.6.5-win (Kazuu / PID 1800000006)
}

// nextendoPIDFromToken validates a "nx2.<b64(pid.username.expiry)>.<b64(hmac)>"
// token signed by the account service (HMAC-SHA256, "nex:" prefix).
func nextendoPIDFromToken(s string) (uint64, bool) {
	if len(nextendoSecret) == 0 || !strings.HasPrefix(s, "nx2.") {
		return 0, false
	}
	parts := strings.Split(s[len("nx2."):], ".")
	if len(parts) != 2 {
		return 0, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, false
	}
	mac := hmac.New(sha256.New, nextendoSecret)
	mac.Write([]byte("nex:" + string(raw)))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(parts[1])) {
		return 0, false
	}
	if revokedNexPayloads[string(raw)] { // jeton fuité (release 1.6.5-win) — refusé malgré une signature valide
		return 0, false
	}
	f := strings.SplitN(string(raw), ".", 3) // pid.username.expiry
	if len(f) != 3 {
		return 0, false
	}
	pid, err := strconv.ParseUint(f[0], 10, 64)
	if err != nil {
		return 0, false
	}
	if exp, err := strconv.ParseInt(f[2], 10, 64); err != nil || time.Now().Unix() > exp {
		return 0, false
	}
	return pid, true
}

// loadNextendoSecret loads the shared NEX-token signing secret the SAME way
// nextendo-account does (its loadSecret): env NEXTENDO_SECRET as raw bytes if set,
// otherwise hex-decode the shared key file (NEXTENDO_SECRET_FILE, default
// nextendo_secret.key). The deployed account has no env → it hex-decodes the file,
// so the game server must too or the HMAC won't match and every nx2 token is rejected.
func loadNextendoSecret() []byte {
	if v := os.Getenv("NEXTENDO_SECRET"); v != "" {
		return []byte(v)
	}
	path := envOr("NEXTENDO_SECRET_FILE", "nextendo_secret.key")
	if b, err := os.ReadFile(path); err == nil {
		if dec, derr := hex.DecodeString(strings.TrimSpace(string(b))); derr == nil && len(dec) >= 16 {
			return dec
		}
	}
	return nil
}

// anonymousPID derives a stable PID in the NEX user range from a username.
func anonymousPID(username string) uint64 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(username))
	return 1800000000 + uint64(h.Sum32()%100000000)
}

func logRMC(tag string) func(*nex.Connection, *nex.RMCMessage) {
	return func(c *nex.Connection, req *nex.RMCMessage) {
		fmt.Printf("[MK8 %s] pid=%d proto=%#x method=%d call=%d\n", tag, c.PID, req.Protocol, req.Method, req.CallID)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envOrInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// requireSignedToken : quand true, seule une identite prouvee par un jeton nx2 SIGNE est
// acceptee au LoginEx ; un PID nu est refuse. Desactive par defaut car l emulateur
// actuellement distribue envoie encore le PID nu — a activer apres la prochaine release.
func requireSignedToken() bool {
	v := os.Getenv("NEXTENDO_REQUIRE_SIGNED_TOKEN")
	return v == "1" || v == "true"
}
