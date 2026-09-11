package gonsuauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// challengeMethod adalah satu-satunya metode PKCE yang dipakai.
//
// `plain` sengaja tidak didukung. Ia mengirim verifier apa adanya pada
// permintaan authorize, sehingga siapa pun yang dapat membaca alamat itu dapat
// menukar code-nya sendiri — yang berarti PKCE tidak menutup apa pun.
const challengeMethod = "S256"

// Options adalah konfigurasi SDK login.
//
// Nilainya datang dari GONSU: pada cloud lewat Secret aplikasi, pada self-host
// lewat agent di `/v1/oidc`. Produk tidak menyusun satu pun di antaranya
// sendiri — produk yang menebak `redirect_uri` akan menebak berbeda dari yang
// terdaftar, dan penyedia identitas menolaknya tanpa menyebut nilai mana yang
// ia harapkan.
type Options struct {
	// Issuer WAJIB sama persis dengan klaim `iss` pada token. Beda satu
	// karakter — imbuhan `/oidc`, garis miring di ujung — sudah cukup membuat
	// orang yang sama menjadi orang lain. Ini bukan kemungkinan teoretis:
	// satu perubahan bentuk URL issuer pernah memecah setiap akun menjadi dua.
	Issuer string
	// ClientID dari GONSU. Bukan rahasia.
	ClientID string
	// ClientSecret KOSONG untuk pemasangan self-host: di sana client-nya
	// publik dan PKCE yang menggantikan perannya.
	ClientSecret string
	// RedirectURI wajib sama persis dengan yang didaftarkan GONSU.
	RedirectURI string

	// DiscoveryURL boleh berbeda dari Issuer, dan itu keadaan yang nyata:
	// pemasangan di dalam cluster menempuh alamat dalam, sedangkan `iss` yang
	// ditandatangani harus alamat publik yang juga dapat dibuka browser.
	// Kosong berarti diturunkan dari Issuer.
	DiscoveryURL string

	// Scopes kosong berarti openid, profile, email.
	Scopes []string

	// ClockSkew adalah toleransi selisih jam terhadap penyedia identitas.
	// Nol berarti DefaultClockSkew.
	ClockSkew time.Duration
	// RecheckInterval dan OfflineGrace adalah kebijakan sesi.
	//
	// Nol berarti nilai bawaan. Keduanya diserahkan GONSU lewat
	// GONSU_OIDC_RECHECK_SECONDS dan GONSU_OIDC_OFFLINE_GRACE_SECONDS, supaya
	// kebijakan dapat diubah tanpa merilis ulang setiap produk yang sudah
	// terpasang di server pelanggan yang tidak dapat dihubungi.
	RecheckInterval time.Duration
	OfflineGrace    time.Duration
	// JWKSCacheTTL nol berarti DefaultJWKSCacheTTL.
	JWKSCacheTTL time.Duration

	// HTTPClient boleh diisi test. Nil berarti client dengan tenggat wajar.
	HTTPClient *http.Client

	now func() time.Time
}

// Nilai bawaan.
const (
	// DefaultClockSkew 60 detik. Jam yang meleset beberapa detik adalah
	// keadaan biasa pada server yang tidak menyelaraskan waktunya, dan menolak
	// token karenanya menghasilkan kegagalan login yang tidak dapat
	// dijelaskan siapa pun.
	DefaultClockSkew = time.Minute
	// DefaultJWKSCacheTTL 1 jam. Rotasi kunci tetap tertangkap lebih cepat
	// dari ini, karena `kid` yang tidak dikenal memaksa pengambilan ulang.
	DefaultJWKSCacheTTL = time.Hour
)

// Client memulai dan menyelesaikan login.
type Client struct {
	options Options
	http    *http.Client
	now     func() time.Time

	mu   sync.Mutex
	meta *metadata
	keys *keySet
}

// New menyiapkan SDK login.
//
// TIDAK menghubungi penyedia identitas: dokumen discovery diambil saat
// dibutuhkan. Produk yang gagal start karena penyedia identitas sedang lambat
// adalah produk yang berhenti melayani orang yang SUDAH masuk — kegagalan yang
// jauh lebih besar daripada login baru yang tertunda.
func New(options Options) (*Client, error) {
	var kurang []string
	if strings.TrimSpace(options.Issuer) == "" {
		kurang = append(kurang, "Issuer")
	}
	if strings.TrimSpace(options.ClientID) == "" {
		kurang = append(kurang, "ClientID")
	}
	if strings.TrimSpace(options.RedirectURI) == "" {
		kurang = append(kurang, "RedirectURI")
	}
	if len(kurang) > 0 {
		return nil, fmt.Errorf("konfigurasi login belum lengkap: %s", strings.Join(kurang, ", "))
	}

	if options.DiscoveryURL == "" {
		options.DiscoveryURL = defaultDiscoveryURL(options.Issuer)
	}
	if len(options.Scopes) == 0 {
		// `offline_access` WAJIB ada: tanpanya penyedia identitas tidak
		// menerbitkan refresh token, dan tanpa refresh token pencabutan orang
		// TIDAK PERNAH menjangkau sesi yang sudah berjalan.
		//
		// Produk yang menyetel Scopes sendiri memikul akibatnya, dan
		// VerifySession menolak sesi tanpa refresh token dengan sebab yang
		// menyebutkannya.
		options.Scopes = []string{"openid", "profile", "email", "offline_access"}
	}
	if options.ClockSkew <= 0 {
		options.ClockSkew = DefaultClockSkew
	}
	if options.RecheckInterval <= 0 {
		options.RecheckInterval = DefaultRecheckInterval
	}
	if options.OfflineGrace <= 0 {
		options.OfflineGrace = DefaultOfflineGrace
	}
	if options.JWKSCacheTTL <= 0 {
		options.JWKSCacheTTL = DefaultJWKSCacheTTL
	}
	if options.HTTPClient == nil {
		options.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	if options.now == nil {
		options.now = time.Now
	}

	return &Client{options: options, http: options.HTTPClient, now: options.now}, nil
}

// Pending adalah keadaan yang HARUS disimpan produk sampai pengguna kembali.
//
// Ketiganya wajib disimpan pada sesi sementara di sisi produk — cookie
// bertanda tangan, atau penyimpanan sesi apa pun yang dimilikinya — dan
// dibandingkan kembali di HandleCallback. Menyimpannya di tempat yang dapat
// dibaca atau ditulis pihak lain membuang seluruh gunanya.
type Pending struct {
	// State menutup CSRF: balikan yang bukan berasal dari login yang kita
	// mulai akan membawa state yang tidak cocok.
	State string
	// Nonce mengikat id_token pada permintaan ini, sehingga token yang sah
	// dari sesi lain tidak dapat dipakai ulang.
	Nonce string
	// Verifier adalah PKCE. Ia TIDAK pernah meninggalkan produk sampai
	// penukaran code, dan itulah yang membuat code yang dicuri tidak berguna.
	Verifier string
}

// StartLogin menyusun alamat authorize beserta keadaan yang harus disimpan.
func (c *Client) StartLogin(ctx context.Context) (authorizeURL string, pending Pending, err error) {
	meta, err := c.metadata(ctx)
	if err != nil {
		return "", Pending{}, err
	}

	state, err := randomString()
	if err != nil {
		return "", Pending{}, err
	}
	nonce, err := randomString()
	if err != nil {
		return "", Pending{}, err
	}
	verifier, err := randomString()
	if err != nil {
		return "", Pending{}, err
	}

	sum := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.options.ClientID},
		"redirect_uri":          {c.options.RedirectURI},
		"scope":                 {strings.Join(c.options.Scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {challengeMethod},
	}

	pemisah := "?"
	if strings.Contains(meta.AuthorizationEndpoint, "?") {
		pemisah = "&"
	}
	return meta.AuthorizationEndpoint + pemisah + query.Encode(),
		Pending{State: state, Nonce: nonce, Verifier: verifier}, nil
}

// ErrStateMismatch berarti balikan tidak berasal dari login yang kita mulai.
var ErrStateMismatch = errors.New("state tidak cocok")

// HandleCallback menukar code lalu memvalidasi id_token SEUTUHNYA.
//
// `state` dibandingkan LEBIH DULU, sebelum satu pun panggilan jaringan: balikan
// yang bukan milik kita tidak boleh sampai menghasilkan penukaran code, karena
// penukaran itu sendiri sudah menjadi tindakan atas nama pengguna.
func (c *Client) HandleCallback(
	ctx context.Context, pending Pending, callbackState, code string,
) (Login, error) {
	if subtle.ConstantTimeCompare([]byte(pending.State), []byte(callbackState)) != 1 ||
		pending.State == "" {
		return Login{}, ErrStateMismatch
	}
	if code == "" {
		return Login{}, errors.New("balikan tidak membawa code")
	}

	meta, err := c.metadata(ctx)
	if err != nil {
		return Login{}, err
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.options.RedirectURI},
		"client_id":     {c.options.ClientID},
		"code_verifier": {pending.Verifier},
	}
	if c.options.ClientSecret != "" {
		form.Set("client_secret", c.options.ClientSecret)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.TokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return Login{}, fmt.Errorf("menyiapkan penukaran code: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := c.http.Do(request)
	if err != nil {
		return Login{}, fmt.Errorf("menukar code: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return Login{}, fmt.Errorf("membaca jawaban penukaran code: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return Login{}, fmt.Errorf("penukaran code ditolak (%d): %s",
			response.StatusCode, ringkas(body))
	}

	var token struct {
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &token); err != nil {
		return Login{}, fmt.Errorf("jawaban penukaran code tidak dapat dibaca: %w", err)
	}
	if token.IDToken == "" {
		return Login{}, fmt.Errorf("%w: penyedia identitas tidak mengirim id_token", ErrInvalidToken)
	}

	claims, err := c.verify(ctx, token.IDToken, pending.Nonce)
	if err != nil {
		return Login{}, err
	}

	// RefreshToken kosong TIDAK menggagalkan login. Orangnya sudah terbukti,
	// dan menolak di sini berarti tidak seorang pun dapat masuk pada penyedia
	// yang tidak menerbitkannya. Yang hilang adalah pencabutan yang menjangkau
	// sesi ini — dan VerifySession menyebutkannya nanti dengan sebab yang
	// jelas, bukan diam-diam menganggapnya sah selamanya.
	return Login{
		Claims:  claims,
		IDToken: token.IDToken,
		Session: SessionState{RefreshToken: token.RefreshToken, LastChecked: c.now()},
	}, nil
}

// verify memeriksa id_token: tanda tangan, penerbit, penerima, waktu, dan nonce.
//
// Kelimanya dijalankan SELALU dan tidak ada yang dapat dimatikan. Yang membuat
// alur ini berbahaya bukan sulitnya, melainkan bahwa melewatkan salah satunya
// tetap menghasilkan login yang berhasil.
func (c *Client) verify(ctx context.Context, idToken, nonce string) (Claims, error) {
	headerRaw, payloadRaw, signature, signed, err := parseSegments(idToken)
	if err != nil {
		return Claims{}, err
	}

	var head header
	if err := json.Unmarshal(headerRaw, &head); err != nil {
		return Claims{}, fmt.Errorf("%w: header bukan JSON", ErrInvalidToken)
	}
	if head.Alg == "none" || head.Alg == "" {
		// `alg: none` adalah token tanpa tanda tangan. Ia harus ditolak
		// SEBELUM apa pun yang lain, karena setiap pemeriksaan sesudahnya akan
		// lulus terhadap isi yang ditulis siapa saja.
		return Claims{}, fmt.Errorf("%w: token tidak ditandatangani", ErrInvalidToken)
	}

	keys, err := c.keySet(ctx)
	if err != nil {
		return Claims{}, err
	}
	key, err := keys.key(ctx, head.Kid)
	if err != nil {
		return Claims{}, err
	}
	if err := verifyECDSA(key, head.Alg, signed, signature); err != nil {
		return Claims{}, err
	}

	claims, err := decodeClaims(payloadRaw)
	if err != nil {
		return Claims{}, err
	}

	if claims.Issuer != c.options.Issuer {
		return Claims{}, fmt.Errorf("%w: penerbit %q, seharusnya %q",
			ErrInvalidToken, claims.Issuer, c.options.Issuer)
	}
	if !contains(claims.Audience, c.options.ClientID) {
		return Claims{}, fmt.Errorf("%w: token bukan untuk client ini", ErrInvalidToken)
	}
	if claims.Subject == "" {
		return Claims{}, fmt.Errorf("%w: token tanpa subject", ErrInvalidToken)
	}

	sekarang := c.now()
	if claims.ExpiresAt == 0 {
		return Claims{}, fmt.Errorf("%w: token tanpa masa berlaku", ErrInvalidToken)
	}
	if sekarang.After(time.Unix(claims.ExpiresAt, 0).Add(c.options.ClockSkew)) {
		return Claims{}, fmt.Errorf("%w: token sudah kedaluwarsa", ErrInvalidToken)
	}
	if claims.IssuedAt != 0 &&
		time.Unix(claims.IssuedAt, 0).After(sekarang.Add(c.options.ClockSkew)) {
		return Claims{}, fmt.Errorf("%w: token diterbitkan di masa depan", ErrInvalidToken)
	}

	// Nonce dibandingkan TERAKHIR di antara pemeriksaan isi, tetapi tetap
	// wajib: tanpanya, id_token sah yang dipanen dari sesi lain dapat dipakai
	// ulang di sini.
	if subtle.ConstantTimeCompare([]byte(nonce), []byte(claims.Nonce)) != 1 {
		return Claims{}, fmt.Errorf("%w: nonce tidak cocok", ErrInvalidToken)
	}
	return claims, nil
}

// metadata mengambil dokumen discovery, sekali.
func (c *Client) metadata(ctx context.Context) (metadata, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.meta != nil {
		return *c.meta, nil
	}
	doc, err := discover(ctx, c.http, c.options.DiscoveryURL, c.options.Issuer)
	if err != nil {
		return metadata{}, err
	}
	c.meta = &doc
	return doc, nil
}

func (c *Client) keySet(ctx context.Context) (*keySet, error) {
	doc, err := c.metadata(ctx)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keys == nil {
		c.keys = newKeySet(doc.JWKSURI, c.http, c.options.JWKSCacheTTL, c.now)
	}
	return c.keys, nil
}

// randomString membangkitkan nilai acak 32 byte.
func randomString() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("membangkitkan nilai acak: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// ringkas memotong jawaban penyedia identitas supaya tidak membanjiri log.
func ringkas(body []byte) string {
	const batas = 200
	if len(body) > batas {
		return string(body[:batas]) + "…"
	}
	return string(body)
}
