package gonsuauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gonsuauth "github.com/gonsutrijayautama/gonsu-one-sdk-go-auth"
)

const (
	kid        = "kunci-uji"
	clientID   = "client-uji"
	redirect   = "https://erp.pabrik-abc.co.id/auth/gonsu/callback"
	organisasi = "org_01M1"
)

// penyedia adalah penyedia identitas tiruan yang menandatangani ES384, sama
// dengan yang dipakai GONSU.
type penyedia struct {
	t      *testing.T
	key    *ecdsa.PrivateKey
	server *httptest.Server
	issuer string

	// kembalikan menentukan id_token yang dikirim endpoint token. Kosong
	// berarti token yang sah.
	kembalikan string
	// verifierDiterima merekam PKCE yang benar-benar dikirim produk.
	verifierDiterima string
}

func penyediaBaru(t *testing.T) *penyedia {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("membuat kunci: %v", err)
	}
	p := &penyedia{t: t, key: key}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                p.issuer,
			"authorization_endpoint":                p.server.URL + "/auth",
			"token_endpoint":                        p.server.URL + "/token",
			"jwks_uri":                              p.server.URL + "/jwks",
			"end_session_endpoint":                  p.server.URL + "/session/end",
			"id_token_signing_alg_values_supported": []string{"ES384"},
			"code_challenge_methods_supported":      []string{"S256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "EC", "use": "sig", "kid": kid, "alg": "ES384", "crv": "P-384",
			"x": base64.RawURLEncoding.EncodeToString(key.X.Bytes()),
			"y": base64.RawURLEncoding.EncodeToString(key.Y.Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.verifierDiterima = r.Form.Get("code_verifier")
		token := p.kembalikan
		if token == "" {
			token = p.tandaTangani(nil)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id_token": token})
	})

	p.server = httptest.NewServer(mux)
	p.issuer = p.server.URL
	t.Cleanup(p.server.Close)
	return p
}

// nonceTerakhir menyimpan nonce yang diminta produk, supaya token tiruan dapat
// membawanya kembali seperti penyedia sungguhan.
var nonceTerakhir string

// tandaTangani menerbitkan id_token; `ubah` boleh mengubah klaimnya lebih dulu.
func (p *penyedia) tandaTangani(ubah func(map[string]any)) string {
	p.t.Helper()

	klaim := map[string]any{
		"iss":           p.issuer,
		"sub":           "usr_01M1",
		"aud":           clientID,
		"nonce":         nonceTerakhir,
		"exp":           time.Now().Add(time.Hour).Unix(),
		"iat":           time.Now().Unix(),
		"email":         "andi@pabrik-abc.co.id",
		organisasiKlaim: organisasi,
	}
	if ubah != nil {
		ubah(klaim)
	}
	return p.jwt(map[string]any{"alg": "ES384", "kid": kid, "typ": "JWT"}, klaim)
}

const organisasiKlaim = "organization_id"

func (p *penyedia) jwt(head, klaim map[string]any) string {
	p.t.Helper()

	enc := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			p.t.Fatalf("menyusun JWT: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	signed := enc(head) + "." + enc(klaim)

	digest := sha512.Sum384([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, p.key, digest[:])
	if err != nil {
		p.t.Fatalf("menandatangani: %v", err)
	}
	signature := make([]byte, 96)
	r.FillBytes(signature[:48])
	s.FillBytes(signature[48:])
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// containsScope memeriksa satu scope pada alamat authorize.
func containsScope(authorizeURL, scope string) bool {
	alamat, err := url.Parse(authorizeURL)
	if err != nil {
		return false
	}
	for _, item := range strings.Split(alamat.Query().Get("scope"), " ") {
		if item == scope {
			return true
		}
	}
	return false
}

func klien(t *testing.T, p *penyedia) *gonsuauth.Client {
	t.Helper()

	client, err := gonsuauth.New(gonsuauth.Options{
		Issuer:      p.issuer,
		ClientID:    clientID,
		RedirectURI: redirect,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

// mulai menjalankan StartLogin lalu mencatat nonce-nya.
func mulai(t *testing.T, client *gonsuauth.Client) (string, gonsuauth.Pending) {
	t.Helper()

	authorizeURL, pending, err := client.StartLogin(t.Context())
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	nonceTerakhir = pending.Nonce
	return authorizeURL, pending
}

// ---------------------------------------------------------------------------
// Jalur yang berhasil
// ---------------------------------------------------------------------------

func TestLogin_JalurLengkap(t *testing.T) {
	p := penyediaBaru(t)
	client := klien(t, p)

	authorizeURL, pending := mulai(t, client)

	alamat, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatalf("alamat authorize tidak sah: %v", err)
	}
	q := alamat.Query()
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("metode PKCE = %q, mau S256", q.Get("code_challenge_method"))
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge") == pending.Verifier {
		// Challenge adalah HASH dari verifier. Mengirim verifier apa adanya
		// berarti siapa pun yang membaca alamat itu dapat menukar code-nya.
		t.Error("code_challenge bukan hash dari verifier")
	}
	if q.Get("state") != pending.State || q.Get("nonce") != pending.Nonce {
		t.Error("state atau nonce tidak ikut ke alamat authorize")
	}
	if q.Get("redirect_uri") != redirect {
		t.Errorf("redirect_uri = %q", q.Get("redirect_uri"))
	}

	login, err := client.HandleCallback(t.Context(), pending, pending.State, "kode-uji")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if login.Claims.Subject != "usr_01M1" || login.Claims.Email != "andi@pabrik-abc.co.id" {
		t.Errorf("klaim = %+v", login.Claims)
	}
	if login.IDToken == "" {
		t.Error("id_token tidak dikembalikan; produk tidak dapat memakainya saat keluar")
	}
	// PKCE benar-benar dikirim: tanpa ini, code yang dicuri tetap dapat
	// ditukar orang lain.
	if p.verifierDiterima != pending.Verifier {
		t.Error("code_verifier tidak dikirim saat menukar code")
	}
}

// ---------------------------------------------------------------------------
// Yang salahnya TIDAK TERLIHAT — inilah alasan SDK ini ada
// ---------------------------------------------------------------------------

func TestLogin_StateSalahDitolakSebelumMenyentuhJaringan(t *testing.T) {
	p := penyediaBaru(t)
	client := klien(t, p)
	_, pending := mulai(t, client)

	p.verifierDiterima = "belum-dipanggil"
	_, err := client.HandleCallback(t.Context(), pending, "state-penyerang", "kode-uji")
	if !errors.Is(err, gonsuauth.ErrStateMismatch) {
		t.Fatalf("galat = %v, mau ErrStateMismatch", err)
	}
	// Penukaran code adalah tindakan atas nama pengguna. Balikan yang bukan
	// milik kita tidak boleh sampai menghasilkannya.
	if p.verifierDiterima != "belum-dipanggil" {
		t.Error("code ditukar padahal state tidak cocok")
	}
}

func TestLogin_TokenYangSalahDitolak(t *testing.T) {
	kasus := []struct {
		nama string
		ubah func(*penyedia, map[string]any)
	}{
		{"penerbit lain", func(_ *penyedia, k map[string]any) { k["iss"] = "https://penyerang.example" }},
		{"untuk client lain", func(_ *penyedia, k map[string]any) { k["aud"] = "client-lain" }},
		{"sudah kedaluwarsa", func(_ *penyedia, k map[string]any) {
			k["exp"] = time.Now().Add(-2 * time.Hour).Unix()
		}},
		{"diterbitkan di masa depan", func(_ *penyedia, k map[string]any) {
			k["iat"] = time.Now().Add(2 * time.Hour).Unix()
		}},
		{"nonce sesi lain", func(_ *penyedia, k map[string]any) { k["nonce"] = "nonce-lain" }},
		{"tanpa nonce", func(_ *penyedia, k map[string]any) { delete(k, "nonce") }},
		{"tanpa masa berlaku", func(_ *penyedia, k map[string]any) { delete(k, "exp") }},
		{"tanpa subject", func(_ *penyedia, k map[string]any) { delete(k, "sub") }},
	}

	for _, kasus := range kasus {
		t.Run(kasus.nama, func(t *testing.T) {
			p := penyediaBaru(t)
			client := klien(t, p)
			_, pending := mulai(t, client)

			p.kembalikan = p.tandaTangani(func(k map[string]any) { kasus.ubah(p, k) })

			_, err := client.HandleCallback(t.Context(), pending, pending.State, "kode-uji")
			if !errors.Is(err, gonsuauth.ErrInvalidToken) {
				t.Fatalf("galat = %v, mau ErrInvalidToken", err)
			}
		})
	}
}

// TestLogin_TokenTanpaTandaTanganDitolak menjaga lubang paling tua pada JWT.
//
// `alg: none` menghasilkan token yang isinya dapat ditulis siapa saja, dan
// setiap pemeriksaan sesudahnya akan LULUS terhadap isi itu.
func TestLogin_TokenTanpaTandaTanganDitolak(t *testing.T) {
	p := penyediaBaru(t)
	client := klien(t, p)
	_, pending := mulai(t, client)

	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	klaim, _ := json.Marshal(map[string]any{
		"iss": p.issuer, "sub": "usr_penyerang", "aud": clientID,
		"nonce": pending.Nonce, "exp": time.Now().Add(time.Hour).Unix(),
	})
	p.kembalikan = head + "." + base64.RawURLEncoding.EncodeToString(klaim) + "."

	if _, err := client.HandleCallback(t.Context(), pending, pending.State, "kode-uji"); !errors.Is(
		err, gonsuauth.ErrInvalidToken) {
		t.Fatalf("galat = %v, mau ErrInvalidToken", err)
	}
}

// TestLogin_TandaTanganDiubahDitolak menjaga hal yang paling dasar dan paling
// mudah dianggap sudah beres.
func TestLogin_TandaTanganDiubahDitolak(t *testing.T) {
	p := penyediaBaru(t)
	client := klien(t, p)
	_, pending := mulai(t, client)

	sah := p.tandaTangani(nil)
	bagian := strings.Split(sah, ".")
	// Satu bit pada tanda tangan.
	rusak := []byte(bagian[2])
	if rusak[0] == 'A' {
		rusak[0] = 'B'
	} else {
		rusak[0] = 'A'
	}
	p.kembalikan = bagian[0] + "." + bagian[1] + "." + string(rusak)

	if _, err := client.HandleCallback(t.Context(), pending, pending.State, "kode-uji"); !errors.Is(
		err, gonsuauth.ErrInvalidToken) {
		t.Fatalf("galat = %v, mau ErrInvalidToken", err)
	}
}

// TestDiscovery_IssuerYangTidakCocokDitolak menjaga jebakan yang sudah pernah
// menggigit project ini.
//
// Endpoint diambil dari dokumen discovery sedangkan `iss` dibandingkan dengan
// nilai yang dikonfigurasi. Membiarkan keduanya berbeda berarti produk menukar
// code di satu tempat dan mempercayai token yang mengaku dari tempat lain.
func TestDiscovery_IssuerYangTidakCocokDitolak(t *testing.T) {
	p := penyediaBaru(t)
	p.issuer = "https://penerbit-lain.example"

	client, err := gonsuauth.New(gonsuauth.Options{
		Issuer:       p.server.URL,
		DiscoveryURL: p.server.URL + "/.well-known/openid-configuration",
		ClientID:     clientID,
		RedirectURI:  redirect,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, _, err := client.StartLogin(t.Context()); err == nil {
		t.Fatal("issuer yang tidak cocok diterima")
	}
}

// ---------------------------------------------------------------------------
// Tenant
// ---------------------------------------------------------------------------

func TestEnsureGranted(t *testing.T) {
	t.Parallel()

	tabel := func(daftar ...string) gonsuauth.SubjectLookup {
		return func(_ context.Context, subject string) (bool, error) {
			for _, item := range daftar {
				if item == subject {
					return true, nil
				}
			}
			return false, nil
		}
	}
	andi := gonsuauth.Claims{Subject: "usr_andi"}

	if err := gonsuauth.EnsureGranted(t.Context(), andi, tabel("usr_andi")); err != nil {
		t.Fatalf("orang yang sudah diberi akses ditolak: %v", err)
	}

	// Token SAH milik orang dari pemasangan lain. Pemasangan self-host berbagi
	// satu penyedia identitas dengan seluruh pelanggan, jadi ini bukan kasus
	// teoretis.
	if err := gonsuauth.EnsureGranted(t.Context(), andi, tabel("usr_lain")); !errors.Is(
		err, gonsuauth.ErrNotGranted) {
		t.Fatalf("galat = %v, mau ErrNotGranted", err)
	}

	// Tidak menyebutkan cara mencari adalah GALAT, bukan lulus diam-diam.
	if err := gonsuauth.EnsureGranted(t.Context(), andi, nil); !errors.Is(
		err, gonsuauth.ErrLookupMissing) {
		t.Fatalf("galat = %v, mau ErrLookupMissing", err)
	}
}

// TestEnsureGranted_GagalMencariBukanBerartiDitolak menjaga perbedaan yang
// sama pentingnya dengan pada sesi.
//
// Database yang sesaat tidak dapat dihubungi bukan pernyataan bahwa orangnya
// tidak berhak. Menyamakannya berarti satu gangguan mengeluarkan setiap orang
// sekaligus — dan produk yang menangkap ErrNotGranted akan mengarahkan mereka
// ke halaman "Anda tidak punya akses", bukan ke halaman galat.
func TestEnsureGranted_GagalMencariBukanBerartiDitolak(t *testing.T) {
	t.Parallel()

	rusak := func(context.Context, string) (bool, error) {
		return false, errors.New("database sedang tidak dapat dihubungi")
	}
	err := gonsuauth.EnsureGranted(t.Context(), gonsuauth.Claims{Subject: "usr_andi"}, rusak)
	if err == nil {
		t.Fatal("kegagalan mencari tidak dilaporkan")
	}
	if errors.Is(err, gonsuauth.ErrNotGranted) {
		t.Fatal("kegagalan mencari disamakan dengan tidak berhak")
	}
}

// ---------------------------------------------------------------------------
// Konfigurasi
// ---------------------------------------------------------------------------

func TestNew_MenolakKonfigurasiTidakLengkap(t *testing.T) {
	if _, err := gonsuauth.New(gonsuauth.Options{ClientID: clientID}); err == nil {
		t.Fatal("konfigurasi tanpa issuer diterima")
	}
	if _, err := gonsuauth.New(gonsuauth.Options{Issuer: "https://a", ClientID: "b"}); err == nil {
		t.Fatal("konfigurasi tanpa redirect_uri diterima")
	}
}

// TestNew_TidakMenghubungiPenyediaIdentitas menjaga supaya produk tetap dapat
// start ketika penyedia identitas sedang lambat.
//
// Produk yang gagal start karenanya berhenti melayani orang yang SUDAH masuk —
// kegagalan yang jauh lebih besar daripada login baru yang tertunda.
func TestNew_TidakMenghubungiPenyediaIdentitas(t *testing.T) {
	if _, err := gonsuauth.New(gonsuauth.Options{
		Issuer:      "https://alamat-yang-tidak-ada.invalid",
		ClientID:    clientID,
		RedirectURI: redirect,
	}); err != nil {
		t.Fatalf("New menghubungi penyedia identitas: %v", err)
	}
}

// TestLogin_MemintaOfflineAccess menjaga syarat yang tanpanya seluruh mekanisme
// di atas tidak pernah berjalan.
//
// Tanpa scope `offline_access`, penyedia identitas tidak menerbitkan refresh
// token — dan pencabutan orang tidak akan pernah menjangkau sesi mana pun.
func TestLogin_MemintaOfflineAccess(t *testing.T) {
	p := penyediaBaru(t)
	client := klien(t, p)

	authorizeURL, _ := mulai(t, client)
	if !containsScope(authorizeURL, "offline_access") {
		t.Fatalf("scope offline_access tidak diminta: %s", authorizeURL)
	}
}
