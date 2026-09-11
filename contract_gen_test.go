package gonsuauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// BERKAS UJI KANONIK UNTUK LOGIN
// ---------------------------------------------------------------------------
//
// sdk/contract/auth-contract.json adalah kontrak LOGIN yang dapat dijalankan,
// dalam bahasa apa pun.
//
// Ada karena alasan yang sama dengan kontrak lisensi, tetapi dengan taruhan
// yang berbeda. Pada lisensi, SDK yang salah baca akan GAGAL — tanda tangannya
// tidak cocok, dan gejalanya langsung terlihat. Pada login, SDK yang salah baca
// tetap BERHASIL: lupa memeriksa `aud`, lupa `nonce`, lupa membandingkan
// penerbit — pengguna tetap masuk, dan tidak ada yang gagal sampai ada yang
// memanfaatkannya.
//
// Karena itu bagian paling berharga di berkas ini bukan token yang harus
// diterima, melainkan yang harus DITOLAK. SDK bahasa baru menjadikannya test:
// "buat berkas ini hijau", dan hijau berarti seluruh penolakan benar-benar
// terjadi.
//
// Yang menghasilkannya adalah sdk/go-auth, BUKAN server: server GONSU tidak
// pernah memverifikasi id_token — yang melakukannya produk. Implementasi
// rujukan karena itu ada di sini, sejalan dengan aturan yang membekukan
// kontrak di implementasi yang benar-benar dipakai lebih dulu.
//
//	go test ./ -run TestAuthContract -update-auth-contract

var updateAuthContract = flag.Bool("update-auth-contract", false,
	"tulis ulang sdk/contract/auth-contract.json dari kode hari ini")

// Nilai-nilai yang DIPATOK. Kunci acak membuat berkas berubah tiap dijalankan,
// dan berkas yang selalu berubah berhenti dibaca siapa pun.
const (
	contractKid      = "kontrak-auth-1"
	contractIssuer   = "https://id.gonsu.example/oidc"
	contractClientID = "app_01M1KONTRAK0000000000000001"
	contractRedirect = "https://erp.contoh.test/auth/gonsu/callback"
	contractNonce    = "nonce-kontrak-0123456789abcdef"
	contractOrg      = "org_01M1KONTRAK0000000000000001"
	contractNowUnix  = 1788688800
	contractSkewSec  = 60
)

// contractPrivateRaw adalah kunci UJI P-384, dipatok di dalam repository
// publik. Ia tidak pernah dipakai menandatangani apa pun yang sungguhan.
var contractPrivateRaw = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
	0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
	0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
}

// tetapReader adalah sumber "acak" yang DAPAT DIULANG.
//
// Tanda tangan ECDSA memakai nilai acak, sehingga token yang dihasilkan akan
// berbeda tiap kali dijalankan — dan berkas kontrak yang berubah tanpa ada yang
// mengubahnya tidak dapat dibedakan dari perubahan yang sungguhan.
type tetapReader struct{ state byte }

func (r *tetapReader) Read(p []byte) (int, error) {
	for i := range p {
		r.state = r.state*31 + 17
		p[i] = r.state
	}
	return len(p), nil
}

type authContract struct {
	Version     int    `json:"version"`
	Description string `json:"description"`

	SigningKey struct {
		Crv      string `json:"crv"`
		Kid      string `json:"kid"`
		Alg      string `json:"alg"`
		PublicX  string `json:"public_x_base64url"`
		PublicY  string `json:"public_y_base64url"`
		PrivateD string `json:"private_d_base64url"`
		Kegunaan string `json:"kegunaan"`
	} `json:"signing_key"`

	Config struct {
		Issuer        string `json:"issuer"`
		ClientID      string `json:"client_id"`
		RedirectURI   string `json:"redirect_uri"`
		ClockSkewSec  int    `json:"clock_skew_seconds"`
		ExpectedNonce string `json:"expected_nonce"`
		NowUnix       int64  `json:"now_unix"`
	} `json:"config"`

	PKCE   []pkceVector   `json:"pkce"`
	Tokens []tokenVector  `json:"tokens"`
	Tenant []tenantVector `json:"tenant"`
}

type pkceVector struct {
	Name      string `json:"name"`
	Verifier  string `json:"code_verifier"`
	Challenge string `json:"code_challenge_s256"`
}

type tokenVector struct {
	Name string `json:"name"`
	Why  string `json:"why"`
	// Accept adalah SATU-SATUNYA yang mengikat. `why` menjelaskan kasusnya
	// untuk manusia; SDK yang menolak dengan alasan berbeda tetap benar —
	// menolak adalah menolak.
	Accept bool   `json:"accept"`
	Token  string `json:"id_token"`
}

// tenantVector menguji penjagaan "orang ini pernah diberi akses di sini".
//
// BUKAN klaim di dalam token: klaim itu tidak ada, dan alasannya dijelaskan di dokumentasi paket. Yang diuji adalah subject apa yang diterima ketika
// tabel pengguna produk memuat daftar tertentu.
type tenantVector struct {
	Name string `json:"name"`
	Why  string `json:"why"`
	// Subject yang datang di dalam token.
	Subject string `json:"subject"`
	// Granted adalah isi tabel pengguna produk.
	Granted []string `json:"granted_subjects"`
	Accept  bool     `json:"accept"`
}

func contractKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.ParseRawPrivateKey(elliptic.P384(), contractPrivateRaw)
	if err != nil {
		t.Fatalf("membaca kunci kontrak: %v", err)
	}
	return key
}

// contractSign menerbitkan id_token dengan tanda tangan yang dapat diulang.
func contractSign(t *testing.T, key *ecdsa.PrivateKey, head, klaim map[string]any) string {
	t.Helper()

	enc := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("menyusun JWT: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	signed := enc(head) + "." + enc(klaim)

	if head["alg"] == "none" {
		return signed + "."
	}

	digest := sha512.Sum384([]byte(signed))
	r, s, err := ecdsa.Sign(&tetapReader{state: 7}, key, digest[:])
	if err != nil {
		t.Fatalf("menandatangani: %v", err)
	}
	signature := make([]byte, 96)
	r.FillBytes(signature[:48])
	s.FillBytes(signature[48:])
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func buildAuthContract(t *testing.T) authContract {
	t.Helper()

	key := contractKey(t)
	sekarang := int64(contractNowUnix)

	var doc authContract
	doc.Version = 1
	doc.Description = "Kontrak login GONSU One yang dapat dijalankan. Dihasilkan sdk/go-auth " +
		"sebagai implementasi rujukan; setiap SDK menjadikannya test. Yang mengikat hanyalah " +
		"`accept` — SDK yang menolak dengan alasan berbeda tetap benar. Kunci di dalamnya " +
		"kunci UJI, bukan kunci sungguhan."

	doc.SigningKey.Crv = "P-384"
	doc.SigningKey.Kid = contractKid
	doc.SigningKey.Alg = "ES384"
	doc.SigningKey.PublicX = base64.RawURLEncoding.EncodeToString(key.X.Bytes())
	doc.SigningKey.PublicY = base64.RawURLEncoding.EncodeToString(key.Y.Bytes())
	doc.SigningKey.PrivateD = base64.RawURLEncoding.EncodeToString(contractPrivateRaw)
	doc.SigningKey.Kegunaan = "Privatnya disertakan supaya SDK dapat menyusun kasus negatifnya " +
		"sendiri — misalnya token yang ditandatangani kunci asing."

	doc.Config.Issuer = contractIssuer
	doc.Config.ClientID = contractClientID
	doc.Config.RedirectURI = contractRedirect
	doc.Config.ClockSkewSec = contractSkewSec
	doc.Config.ExpectedNonce = contractNonce
	doc.Config.NowUnix = sekarang

	// PKCE: challenge WAJIB hash dari verifier. Mengirim verifier apa adanya
	// berarti PKCE tidak menutup apa pun.
	for _, verifier := range []string{
		"verifier-kontrak-0123456789abcdefghij",
		"a", // pendek: batas bawah tetap harus menghasilkan challenge yang benar
	} {
		sum := sha256.Sum256([]byte(verifier))
		doc.PKCE = append(doc.PKCE, pkceVector{
			Name:      "S256 " + verifier[:1],
			Verifier:  verifier,
			Challenge: base64.RawURLEncoding.EncodeToString(sum[:]),
		})
	}

	head := map[string]any{"alg": "ES384", "kid": contractKid, "typ": "JWT"}
	dasar := func() map[string]any {
		return map[string]any{
			"iss": contractIssuer, "sub": "usr_01M1KONTRAK0000000000000001",
			"aud": contractClientID, "nonce": contractNonce,
			"exp": sekarang + 3600, "iat": sekarang,
			"email": "andi@contoh.test",
		}
	}
	tambah := func(name, why string, accept bool, ubahHead map[string]any, ubah func(map[string]any)) {
		klaim := dasar()
		if ubah != nil {
			ubah(klaim)
		}
		h := head
		if ubahHead != nil {
			h = ubahHead
		}
		doc.Tokens = append(doc.Tokens, tokenVector{
			Name: name, Why: why, Accept: accept, Token: contractSign(t, key, h, klaim),
		})
	}

	tambah("sah", "keadaan biasa: seluruh pemeriksaan lulus", true, nil, nil)
	tambah("aud berupa daftar", "JWT mengizinkan `aud` daftar; keduanya wajib diterima",
		true, nil, func(k map[string]any) { k["aud"] = []any{"lain", contractClientID} })
	tambah("kedaluwarsa dalam toleransi jam",
		"baru lewat beberapa detik; jam yang meleset adalah keadaan biasa",
		true, nil, func(k map[string]any) { k["exp"] = sekarang - contractSkewSec/2 })

	tambah("penerbit lain", "token dari penerbit mana pun akan lulus kalau `iss` tidak diperiksa",
		false, nil, func(k map[string]any) { k["iss"] = "https://penyerang.example" })
	tambah("penerbit hampir sama", "beda imbuhan saja sudah cukup membuat orang menjadi orang lain",
		false, nil, func(k map[string]any) { k["iss"] = contractIssuer + "/" })
	tambah("untuk client lain", "token sah milik aplikasi lain tidak boleh diterima di sini",
		false, nil, func(k map[string]any) { k["aud"] = "client_lain" })
	tambah("aud daftar tanpa client ini", "daftar yang tidak memuat kita tetap bukan untuk kita",
		false, nil, func(k map[string]any) { k["aud"] = []any{"lain", "lainnya"} })
	tambah("sudah kedaluwarsa", "di luar toleransi jam", false, nil,
		func(k map[string]any) { k["exp"] = sekarang - 7200 })
	tambah("tanpa exp", "token tanpa masa berlaku berlaku selamanya", false, nil,
		func(k map[string]any) { delete(k, "exp") })
	tambah("diterbitkan di masa depan", "jam penyerang, bukan jam penerbit", false, nil,
		func(k map[string]any) { k["iat"] = sekarang + 7200 })
	tambah("nonce sesi lain", "tanpa nonce, token yang dipanen dapat dipakai ulang",
		false, nil, func(k map[string]any) { k["nonce"] = "nonce-lain" })
	tambah("tanpa nonce", "ketiadaan nonce tidak boleh berarti lulus", false, nil,
		func(k map[string]any) { delete(k, "nonce") })
	tambah("tanpa sub", "token tanpa subject tidak menyebut siapa pun", false, nil,
		func(k map[string]any) { delete(k, "sub") })
	tambah("alg none", "isinya dapat ditulis siapa saja; setiap pemeriksaan sesudahnya akan lulus",
		false, map[string]any{"alg": "none", "typ": "JWT"}, nil)
	tambah("kid tidak dikenal", "kunci yang tidak ada di JWKS bukan kunci penerbit",
		false, map[string]any{"alg": "ES384", "kid": "kid-asing", "typ": "JWT"}, nil)

	// Tanda tangan diubah satu karakter.
	sah := contractSign(t, key, head, dasar())
	rusak := []byte(sah)
	rusak[len(rusak)-1] = 'A' + (rusak[len(rusak)-1]+1)%26
	doc.Tokens = append(doc.Tokens, tokenVector{
		Name: "tanda tangan diubah", Why: "satu karakter sudah cukup",
		Accept: false, Token: string(rusak),
	})

	doc.Tenant = []tenantVector{
		{Name: "sudah diberi akses", Why: "keadaan biasa", Accept: true,
			Subject: "usr_kontrak_1", Granted: []string{"usr_kontrak_1", "usr_kontrak_2"}},
		{Name: "belum pernah diberi akses",
			Why:     "token SAH milik orang dari pemasangan lain — pemasangan self-host berbagi satu penyedia identitas",
			Accept:  false,
			Subject: "usr_pemasangan_lain", Granted: []string{"usr_kontrak_1"}},
		{Name: "tabel kosong", Why: "pemasangan yang belum memberi akses kepada siapa pun menolak semua",
			Accept: false, Subject: "usr_kontrak_1", Granted: nil},
		{Name: "token tanpa subject", Why: "token yang tidak menyebut siapa pun tidak dapat dicocokkan",
			Accept: false, Subject: "", Granted: []string{"usr_kontrak_1"}},
	}
	return doc
}

// TestAuthContract_SalinanSama menjaga kedua salinan tetap identik.
//
// BERBEDA DARI KONTRAK LISENSI, dan bedanya bukan pilihan: kontrak lisensi
// dihasilkan ulang lalu dibandingkan byte per byte, dan itu mungkin karena
// Ed25519 DETERMINISTIK menurut spesifikasinya — kunci dan pesan yang sama
// selalu menghasilkan tanda tangan yang sama.
//
// ECDSA tidak. Go mencampurkan keacakan sungguhan bahkan ketika diberi sumber
// acak yang tetap, sehingga menandatangani dua kali menghasilkan token yang
// berbeda. Membandingkan berkas hasil regenerasi karena itu akan SELALU merah,
// dan test yang selalu merah berhenti dibaca siapa pun.
//
// Karena itu berkas ini adalah FIXTURE yang di-commit, bukan artefak yang
// dihasilkan ulang. Yang menjaganya adalah TestAuthContract_VektorDijalankan di
// bawah — ia membaca berkas yang TERSIMPAN dan menuntut kode hari ini masih
// menyepakatinya. Perubahan perilaku yang membuat vektor lama tidak lagi
// berlaku akan merah di sana.
//
// Yang dijaga di sini hanya satu hal, dan hal itu memang mudah terlupa: kedua
// salinan harus sama. SDK yang testdata-nya tertinggal akan tetap hijau memakai
// kontrak lama.
func TestAuthContract_SalinanSama(t *testing.T) {
	if *updateAuthContract {
		tulisKontrak(t)
		return
	}

	kanonik, err := os.ReadFile(kontrakKanonik) //nolint:gosec // path tetap di dalam repository
	if errors.Is(err, os.ErrNotExist) {
		// Module ini juga hidup sebagai repository tersendiri, dan di sana
		// salinan kanonik memang TIDAK ADA: yang didistribusikan hanya SDK-nya.
		//
		// Dilewati, bukan dianggap gagal. Penyimpangan antar salinan hanya
		// MUNGKIN terjadi di tempat kedua salinan ada, yaitu monorepo, dan di
		// sanalah test ini berjalan sungguhan.
		t.Skip("salinan kanonik tidak ada; ini salinan distribusi, bukan monorepo")
	}
	if err != nil {
		t.Fatalf("membaca kontrak %s: %v (jalankan dengan -update-auth-contract)", kontrakKanonik, err)
	}

	salinan, err := os.ReadFile(kontrakSDK) //nolint:gosec // path tetap di dalam repository
	if err != nil {
		t.Fatalf("membaca kontrak %s: %v (jalankan dengan -update-auth-contract)", kontrakSDK, err)
	}
	if string(salinan) != string(kanonik) {
		t.Errorf("salinan kontrak %s berbeda dari yang kanonik.\n"+
			"Perbarui dengan: go test ./ -run TestAuthContract -update-auth-contract", kontrakSDK)
	}
}

// Kedua salinan kontrak auth, dan keduanya sengaja punya nama sendiri.
//
// kontrakKanonik adalah sumber kebenaran yang dibaca SETIAP SDK auth, apa pun
// bahasanya. Ia berada DI LUAR module ini, dan karena itu tidak selalu ada:
// module ini juga didistribusikan sebagai repository tersendiri yang hanya
// memuat SDK-nya.
//
// kontrakSDK adalah salinan yang ikut ke mana pun module ini pergi. Ia SELALU
// ada, dan karena itu dialah yang dipakai menjalankan vektor.
//
// SDK auth bahasa baru menambahkan salinannya sendiri dan menjaga
// kesamaannya dengan cara yang sama; yang tidak melakukannya akan tetap hijau
// memakai kontrak lama, dan penyimpangannya baru terlihat pada produk
// pelanggan.
var (
	kontrakKanonik = filepath.Join("..", "contract", "auth-contract.json")
	kontrakSDK     = filepath.Join("testdata", "auth-contract.json")
)

// tulisKontrak menerbitkan ulang berkas kontrak dari kode hari ini.
//
// Dijalankan DENGAN SADAR lewat -update-auth-contract. Token di dalamnya
// ditandatangani ulang, sehingga seluruh berkas berubah walau tidak ada
// perilaku yang berubah — itu sifat ECDSA, dan itulah sebabnya berkas ini tidak
// dihasilkan ulang di setiap test.
func tulisKontrak(t *testing.T) {
	t.Helper()

	generated, err := json.MarshalIndent(buildAuthContract(t), "", "  ")
	if err != nil {
		t.Fatalf("menyusun kontrak: %v", err)
	}
	generated = append(generated, '\n')

	for _, path := range []string{kontrakKanonik, kontrakSDK} {
		// MkdirAll, bukan MkdirAll tanpa syarat: di salinan distribusi,
		// membuat ../contract/ akan MENERBITKAN kontrak kanonik palsu di
		// repository yang tidak berhak memilikinya.
		if path == kontrakKanonik {
			if _, err := os.Stat(filepath.Dir(path)); errors.Is(err, os.ErrNotExist) {
				t.Logf("dilewati, bukan monorepo: %s", path)
				continue
			}
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("menyiapkan direktori: %v", err)
		}
		if err := os.WriteFile(path, generated, 0o644); err != nil { //nolint:gosec // kontrak memang dibaca semua orang
			t.Fatalf("menulis kontrak: %v", err)
		}
		t.Logf("kontrak ditulis ulang: %s", path)
	}
}

// TestAuthContract_VektorDijalankan menjalankan seluruh vektor terhadap jalur
// verifikasi yang sungguhan.
//
// Tanpa ini, berkas kontrak hanyalah berkas: ia dapat menyimpang dari perilaku
// yang benar-benar dijalankan tanpa satu pun test merah.
func TestAuthContract_VektorDijalankan(t *testing.T) {
	// Dari berkas yang TERSIMPAN, bukan dari yang baru dibangun. Kalau ia
	// dibangun ulang di sini, test ini hanya membuktikan kode menyepakati
	// dirinya sendiri — dan vektor yang tidak lagi berlaku tidak akan pernah
	// ketahuan.
	// Dari salinan SDK, bukan dari yang kanonik: yang kanonik berada di luar
	// module dan tidak ikut ke repository distribusi, sehingga vektornya akan
	// berhenti dijalankan justru di tempat SDK ini dipakai orang lain.
	// Kesamaan keduanya dijaga TestAuthContract_SalinanSama di monorepo.
	raw, err := os.ReadFile(kontrakSDK) //nolint:gosec // path tetap di dalam repository
	if err != nil {
		t.Fatalf("membaca kontrak: %v", err)
	}
	var doc authContract
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("kontrak tidak dapat dibaca: %v", err)
	}
	key := contractKey(t)

	sekarang := time.Unix(doc.Config.NowUnix, 0).UTC()
	client, err := New(Options{
		Issuer:      doc.Config.Issuer,
		ClientID:    doc.Config.ClientID,
		RedirectURI: doc.Config.RedirectURI,
		ClockSkew:   time.Duration(doc.Config.ClockSkewSec) * time.Second,
		now:         func() time.Time { return sekarang },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// JWKS diisi langsung: yang diuji di sini VERIFIKASI, bukan pengambilannya.
	//
	// Alamatnya sengaja tidak dapat dihubungi. `kid` yang tidak dikenal memang
	// memicu pengambilan ulang — itu yang membuat rotasi kunci tidak mematikan
	// login — dan di sini pengambilan itu harus GAGAL, sehingga tokennya
	// ditolak. Memberi alamat yang bekerja akan menyembunyikan vektor itu.
	keys := newKeySet("http://127.0.0.1:1/jwks-tidak-ada", client.http,
		time.Hour, client.now)
	keys.keys = map[string]*ecdsa.PublicKey{doc.SigningKey.Kid: &key.PublicKey}
	keys.segarTil = sekarang.Add(time.Hour)
	keys.terakhirDiambil = sekarang
	client.keys = keys
	client.meta = &metadata{Issuer: doc.Config.Issuer}

	for _, vektor := range doc.Tokens {
		t.Run("token/"+vektor.Name, func(t *testing.T) {
			_, err := client.verify(t.Context(), vektor.Token, doc.Config.ExpectedNonce)
			if vektor.Accept && err != nil {
				t.Fatalf("token yang seharusnya diterima ditolak: %v (%s)", err, vektor.Why)
			}
			if !vektor.Accept && err == nil {
				t.Fatalf("token yang seharusnya DITOLAK diterima — %s", vektor.Why)
			}
		})
	}

	for _, vektor := range doc.Tenant {
		t.Run("tenant/"+vektor.Name, func(t *testing.T) {
			granted := func(_ context.Context, subject string) (bool, error) {
				for _, item := range vektor.Granted {
					if item == subject {
						return true, nil
					}
				}
				return false, nil
			}
			err := EnsureGranted(t.Context(), Claims{Subject: vektor.Subject}, granted)
			if vektor.Accept && err != nil {
				t.Fatalf("tenant yang seharusnya diterima ditolak: %v (%s)", err, vektor.Why)
			}
			if !vektor.Accept && err == nil {
				t.Fatalf("tenant yang seharusnya DITOLAK diterima — %s", vektor.Why)
			}
		})
	}

	for _, vektor := range doc.PKCE {
		t.Run("pkce/"+vektor.Name, func(t *testing.T) {
			sum := sha256.Sum256([]byte(vektor.Verifier))
			if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != vektor.Challenge {
				t.Fatalf("challenge = %q, mau %q", got, vektor.Challenge)
			}
		})
	}
}
