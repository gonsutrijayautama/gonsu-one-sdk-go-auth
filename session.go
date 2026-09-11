package gonsuauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// PENCABUTAN MENJANGKAU SESI YANG SUDAH BERJALAN
// ---------------------------------------------------------------------------
//
// Tanpa ini, orang yang di-offboard kemarin masih bekerja hari ini: sesi produk
// terbit sekali di titik login dan tidak pernah menanyakan ulang apakah
// orangnya masih berhak.
//
// Yang dipakai adalah pemeriksaan berkala yang DITARIK produk, bukan
// back-channel logout yang DIDORONG GONSU. Back-channel lebih
// rapi di cloud dan tidak dapat dipakai sama sekali di self-host: GONSU tidak
// dapat menghubungi produk yang berjalan di jaringan pabrik pelanggan. Yang
// bekerja di kedua mode adalah yang produknya tarik — pola yang sama dengan
// heartbeat lisensi.

// Nilai bawaan kebijakan sesi.
//
// Keduanya diserahkan GONSU lewat Secret aplikasi — `GONSU_OIDC_RECHECK_SECONDS`
// dan `GONSU_OIDC_OFFLINE_GRACE_SECONDS` — supaya kebijakannya dapat diubah
// tanpa merilis ulang setiap produk yang sudah terpasang.
const (
	// DefaultRecheckInterval 15 menit: jeda maksimum sebelum produk menanyakan
	// ulang apakah orangnya masih berhak.
	DefaultRecheckInterval = 15 * time.Minute
	// DefaultOfflineGrace 12 jam, yaitu satu shift kerja.
	//
	// Memutus sesi di tengah shift karena internet pabrik mati adalah reaksi
	// yang tidak dapat dibatalkan terhadap sesuatu yang paling sering sembuh
	// sendiri; menahannya lebih lama berarti orang yang di-offboard kemarin
	// masih bekerja hari ini.
	DefaultOfflineGrace = 12 * time.Hour
)

// ErrSessionExpired berarti sesi TIDAK boleh dilanjutkan.
//
// Dua sebab berbeda berakhir di sini, dan produk memperlakukan keduanya sama:
// GONSU menolak (orangnya dicabut), atau GONSU tidak terjangkau melewati masa
// tenggang. Yang membedakan keduanya hanya catatan log — bagi orang yang
// memakainya, keduanya berarti masuk lagi.
var ErrSessionExpired = errors.New("sesi tidak boleh dilanjutkan")

// SessionState adalah yang DISIMPAN PRODUK bersama sesinya sendiri.
//
// Bukan sesi itu sendiri: cookie, penyimpanan, dan masa berlakunya milik
// produk. Yang di sini hanyalah bahan untuk menjawab satu pertanyaan — apakah
// orang ini masih berhak.
type SessionState struct {
	// RefreshToken RAHASIA. Kosong berarti penyedia identitas tidak
	// menerbitkannya, dan sesi tidak dapat diperiksa ulang sama sekali.
	RefreshToken string
	// LastChecked adalah kapan GONSU terakhir MENGONFIRMASI orangnya masih
	// berhak — bukan kapan sesi dibuat, dan bukan kapan terakhir dipakai.
	LastChecked time.Time
}

// Login adalah hasil login yang selesai.
type Login struct {
	Claims Claims
	// IDToken disimpan produk untuk `id_token_hint` saat keluar. Bukan untuk
	// divalidasi ulang setiap request — produk yang melakukannya mati setiap
	// kali GONSU sesaat tidak terjangkau.
	IDToken string
	// Session adalah bahan pemeriksaan berkala. RefreshToken kosong berarti
	// pencabutan TIDAK akan menjangkau sesi ini.
	Session SessionState
}

// VerifySession memutuskan apakah sebuah sesi boleh dilanjutkan.
//
// Tiga keadaan, dan yang membedakannya bukan hasil melainkan SEBAB:
//
//	belum waktunya diperiksa  -> lanjut, tanpa menyentuh jaringan
//	GONSU menjawab            -> lanjut, dan waktunya disegarkan
//	GONSU MENOLAK             -> ErrSessionExpired, seketika
//	GONSU tak terjangkau      -> lanjut selama masih dalam masa tenggang
//
// Perbedaan antara "menolak" dan "tak terjangkau" adalah inti seluruh
// mekanisme ini. Menyamakannya berarti gangguan jaringan lima menit
// mengeluarkan setiap orang di setiap pelanggan sekaligus — atau, kalau
// disamakan ke arah sebaliknya, orang yang dicabut tetap bekerja selama
// jaringannya kebetulan buruk.
//
// State yang dikembalikan WAJIB disimpan produk: penyedia identitas dapat
// merotasi refresh token pada setiap penukaran, dan menyimpan yang lama berarti
// pemeriksaan berikutnya ditolak walau orangnya masih berhak.
func (c *Client) VerifySession(ctx context.Context, state SessionState) (SessionState, error) {
	if state.RefreshToken == "" {
		// Tidak ada yang dapat diperiksa. Ini BUKAN diperlakukan sebagai sesi
		// yang sah selamanya: tanpa refresh token, pencabutan tidak akan pernah
		// menjangkaunya, dan membiarkannya berarti menjanjikan penjagaan yang
		// tidak ada.
		return state, fmt.Errorf("%w: sesi tanpa refresh token tidak dapat diperiksa ulang",
			ErrSessionExpired)
	}

	sekarang := c.now()
	if sekarang.Sub(state.LastChecked) < c.options.RecheckInterval {
		return state, nil
	}

	baru, err := c.tukarRefreshToken(ctx, state.RefreshToken)
	switch {
	case err == nil:
		return SessionState{RefreshToken: baru, LastChecked: sekarang}, nil

	case errors.Is(err, errRefreshRejected):
		// GONSU menjawab, dan jawabannya tidak. Masa tenggang TIDAK berlaku:
		// ia ada untuk jaringan yang putus, bukan untuk jawaban yang tidak
		// disukai.
		// Keduanya di-wrap: pemanggil dapat memeriksa ErrSessionExpired untuk
		// memutuskan, dan sebab aslinya untuk mencatatnya.
		return state, fmt.Errorf("%w: %w", ErrSessionExpired, err)

	default:
		// Tidak terjangkau. Sesi bertahan sampai masa tenggang habis.
		if sekarang.Sub(state.LastChecked) <= c.options.OfflineGrace {
			return state, nil
		}
		return state, fmt.Errorf(
			"%w: GONSU tidak terjangkau melewati masa tenggang %s (terakhir diperiksa %s)",
			ErrSessionExpired, c.options.OfflineGrace, state.LastChecked.Format(time.RFC3339))
	}
}

// errRefreshRejected menandai penolakan dari penyedia identitas — bukan
// kegagalan menghubunginya.
var errRefreshRejected = errors.New("penyedia identitas menolak refresh token")

// tukarRefreshToken menukar refresh token dan mengembalikan yang berlaku
// berikutnya.
func (c *Client) tukarRefreshToken(ctx context.Context, refreshToken string) (string, error) {
	meta, err := c.metadata(ctx)
	if err != nil {
		return "", err
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {c.options.ClientID},
	}
	if c.options.ClientSecret != "" {
		form.Set("client_secret", c.options.ClientSecret)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.TokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("menyiapkan penukaran refresh token: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := c.http.Do(request)
	if err != nil {
		return "", fmt.Errorf("menghubungi penyedia identitas: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("membaca jawaban penukaran: %w", err)
	}

	// 4xx adalah JAWABAN: penyedia identitas dapat dihubungi dan ia menolak.
	// 5xx bukan — server yang sedang rusak bukan pernyataan bahwa orangnya
	// dicabut, dan memperlakukannya begitu berarti gangguan di sisi penyedia
	// mengeluarkan setiap orang sekaligus.
	if response.StatusCode >= 400 && response.StatusCode < 500 {
		return "", fmt.Errorf("%w (%d): %s", errRefreshRejected, response.StatusCode, ringkas(body))
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("penyedia identitas menjawab %d: %s",
			response.StatusCode, ringkas(body))
	}

	var token struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &token); err != nil {
		return "", fmt.Errorf("jawaban penukaran tidak dapat dibaca: %w", err)
	}
	if token.RefreshToken == "" {
		// Penyedia yang tidak merotasi mengembalikan yang lama tetap berlaku.
		return refreshToken, nil
	}
	return token.RefreshToken, nil
}
