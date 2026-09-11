package gonsuauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// sesiKlien membuat client yang jam dan endpoint tokennya dikuasai test.
//
// Test ini berada DI DALAM paket supaya jamnya dapat disetel tanpa menambah
// API khusus test ke permukaan publik. API yang hanya ada demi test akan
// dipakai orang untuk hal lain, dan sesudah itu tidak dapat dicabut lagi.
func sesiKlien(t *testing.T, tokenEndpoint string, sekarang time.Time) *Client {
	t.Helper()

	client, err := New(Options{
		Issuer:      "https://id.uji.example",
		ClientID:    "client-uji-sesi",
		RedirectURI: "https://erp.uji.example/cb",
		now:         func() time.Time { return sekarang },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Discovery dilewati: yang diuji di sini KEBIJAKAN sesi, bukan
	// pengambilan dokumennya.
	client.meta = &metadata{
		Issuer:        client.options.Issuer,
		TokenEndpoint: tokenEndpoint,
	}
	return client
}

// TestSession_BelumWaktunyaTidakMenyentuhJaringan menjaga supaya pemeriksaan
// berkala tidak berubah menjadi pemeriksaan setiap request.
//
// Produk yang menanyakan GONSU pada setiap permintaan akan mati setiap kali
// GONSU sesaat tidak terjangkau — kegagalan yang persis sama dengan yang
// dihindari lisensi dengan menyimpan lease ke disk.
func TestSession_BelumWaktunyaTidakMenyentuhJaringan(t *testing.T) {
	t.Parallel()

	var dipanggil int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		dipanggil++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	sekarang := time.Now()
	client := sesiKlien(t, server.URL, sekarang)

	state := SessionState{
		RefreshToken: "rt-1",
		LastChecked:  sekarang.Add(-time.Minute), // baru semenit lalu
	}
	baru, err := client.VerifySession(t.Context(), state)
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if dipanggil != 0 {
		t.Errorf("jaringan disentuh %d kali padahal belum waktunya", dipanggil)
	}
	if baru.LastChecked != state.LastChecked {
		t.Error("waktu pemeriksaan berubah padahal tidak ada pemeriksaan")
	}
}

// TestSession_DitolakLangsungMati adalah inti seluruh mekanisme ini.
//
// GONSU menjawab, dan jawabannya tidak — orangnya dicabut. Masa tenggang TIDAK
// berlaku: ia ada untuk jaringan yang putus, bukan untuk jawaban yang tidak
// disukai.
func TestSession_DitolakLangsungMati(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	t.Cleanup(server.Close)

	sekarang := time.Now()
	client := sesiKlien(t, server.URL, sekarang)

	state := SessionState{
		RefreshToken: "rt-dicabut",
		// Masih jauh di dalam masa tenggang — dan itu tidak menolongnya.
		LastChecked: sekarang.Add(-20 * time.Minute),
	}
	if _, err := client.VerifySession(t.Context(), state); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("galat = %v, mau ErrSessionExpired", err)
	}
}

// TestSession_TidakTerjangkauBertahanSampaiTenggangHabis menjaga arah
// sebaliknya, dan yang salahnya jauh lebih terasa.
//
// Menyamakan "tidak terjangkau" dengan "ditolak" berarti gangguan jaringan lima
// menit mengeluarkan setiap orang di setiap pelanggan sekaligus.
func TestSession_TidakTerjangkauBertahanSampaiTenggangHabis(t *testing.T) {
	t.Parallel()

	// 5xx: server dapat dihubungi tetapi sedang rusak. Itu BUKAN pernyataan
	// bahwa orangnya dicabut.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)

	sekarang := time.Now()
	client := sesiKlien(t, server.URL, sekarang)

	// Di dalam masa tenggang 12 jam: bertahan.
	masihBoleh := SessionState{
		RefreshToken: "rt-1", LastChecked: sekarang.Add(-6 * time.Hour),
	}
	if _, err := client.VerifySession(t.Context(), masihBoleh); err != nil {
		t.Fatalf("sesi dimatikan padahal hanya GONSU yang bermasalah: %v", err)
	}

	// Lewat masa tenggang: mati.
	sudahLewat := SessionState{
		RefreshToken: "rt-1", LastChecked: sekarang.Add(-13 * time.Hour),
	}
	if _, err := client.VerifySession(t.Context(), sudahLewat); !errors.Is(
		err, ErrSessionExpired) {
		t.Fatalf("galat = %v, mau ErrSessionExpired", err)
	}
}

// TestSession_RefreshTokenYangDirotasiDikembalikan menjaga hal yang gagalnya
// tertunda satu putaran.
//
// Penyedia identitas dapat merotasi refresh token pada setiap penukaran.
// Menyimpan yang lama membuat pemeriksaan BERIKUTNYA ditolak walau orangnya
// masih berhak — dan gejalanya orang yang tiba-tiba dikeluarkan tanpa sebab.
func TestSession_RefreshTokenYangDirotasiDikembalikan(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"refresh_token":"rt-baru"}`))
	}))
	t.Cleanup(server.Close)

	sekarang := time.Now()
	client := sesiKlien(t, server.URL, sekarang)

	baru, err := client.VerifySession(t.Context(), SessionState{
		RefreshToken: "rt-lama", LastChecked: sekarang.Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if baru.RefreshToken != "rt-baru" {
		t.Errorf("refresh token = %q, mau rt-baru", baru.RefreshToken)
	}
	if !baru.LastChecked.Equal(sekarang) {
		t.Error("waktu pemeriksaan tidak disegarkan")
	}
}

// TestSession_TanpaRefreshTokenDitolakDenganSebab menjaga supaya ketiadaan
// penjagaan tidak terbaca sebagai penjagaan yang lulus.
//
// Sesi tanpa refresh token tidak akan PERNAH dijangkau pencabutan.
// Membiarkannya berarti menjanjikan penjagaan yang tidak ada.
func TestSession_TanpaRefreshTokenDitolakDenganSebab(t *testing.T) {
	t.Parallel()

	client := sesiKlien(t, "http://127.0.0.1:1/token", time.Now())

	_, err := client.VerifySession(t.Context(), SessionState{LastChecked: time.Now()})
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("galat = %v, mau ErrSessionExpired", err)
	}
}
