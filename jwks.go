package gonsuauth

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// jwk adalah satu kunci publik menurut penyedia identitas.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Use string `json:"use"`
}

// keySet memegang kunci publik penyedia identitas beserta masa segarnya.
//
// Di-cache karena JWKS berubah jarang dan setiap login membacanya. Tetapi
// cache-nya DAPAT DIPAKSA SEGAR: rotasi kunci menghasilkan `kid` yang belum
// dikenal, dan menolak token karenanya berarti setiap rotasi kunci penyedia
// identitas mematikan login seluruh pelanggan sampai cache kedaluwarsa
// sendiri.
type keySet struct {
	url  string
	http *http.Client
	ttl  time.Duration
	now  func() time.Time

	mu       sync.Mutex
	keys     map[string]*ecdsa.PublicKey
	segarTil time.Time
	// terakhirDiambil membatasi pengambilan ulang saat `kid` tidak dikenal.
	// Tanpa batas ini, token dengan `kid` acak dari penyerang menjadi cara
	// memaksa produk menghantam penyedia identitas sekencang yang ia mau.
	terakhirDiambil time.Time
}

// minRefetch adalah jeda minimum antar pengambilan paksa.
const minRefetch = time.Minute

func newKeySet(url string, client *http.Client, ttl time.Duration, now func() time.Time) *keySet {
	return &keySet{url: url, http: client, ttl: ttl, now: now, keys: map[string]*ecdsa.PublicKey{}}
}

// key mengembalikan kunci publik untuk sebuah `kid`.
func (k *keySet) key(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	sekarang := k.now()
	if key, ada := k.keys[kid]; ada && sekarang.Before(k.segarTil) {
		return key, nil
	}

	// Belum dikenal, atau cache sudah lewat. Keduanya berarti mengambil ulang —
	// dan yang pertama itulah yang membuat rotasi kunci tidak mematikan login.
	if !sekarang.Before(k.terakhirDiambil.Add(minRefetch)) || sekarang.After(k.segarTil) {
		if err := k.fetchLocked(ctx); err != nil {
			return nil, err
		}
	}

	key, ada := k.keys[kid]
	if !ada {
		return nil, fmt.Errorf("%w: kunci %q tidak dikenal penyedia identitas", ErrInvalidToken, kid)
	}
	return key, nil
}

func (k *keySet) fetchLocked(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return fmt.Errorf("menyiapkan permintaan JWKS: %w", err)
	}

	response, err := k.http.Do(request)
	if err != nil {
		return fmt.Errorf("mengambil JWKS: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS dijawab %d", response.StatusCode)
	}

	var isi struct {
		Keys []jwk `json:"keys"`
	}
	// Dibatasi: JWKS yang wajar berukuran kilobyte, dan yang menjawab di alamat
	// itu belum tentu penyedia identitas.
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&isi); err != nil {
		return fmt.Errorf("JWKS tidak dapat dibaca: %w", err)
	}

	k.terakhirDiambil = k.now()
	baru := make(map[string]*ecdsa.PublicKey, len(isi.Keys))
	for _, kunci := range isi.Keys {
		// Hanya EC. RSA sengaja tidak didukung: penyedia identitas GONSU
		// menandatangani dengan ES384, dan menerima algoritma yang tidak
		// dipakai hanya menambah permukaan tanpa menambah kemampuan.
		if kunci.Kty != "EC" || kunci.Kid == "" {
			continue
		}
		if kunci.Use != "" && kunci.Use != "sig" {
			continue
		}
		key, err := kunci.publicKey()
		if err != nil {
			// Satu kunci yang tidak dapat dibaca tidak boleh membuang sisanya:
			// penyedia identitas dapat menyajikan kunci untuk algoritma yang
			// tidak kita pakai.
			continue
		}
		baru[kunci.Kid] = key
	}
	if len(baru) == 0 {
		return fmt.Errorf("JWKS tidak memuat satu pun kunci EC yang dapat dipakai")
	}

	k.keys = baru
	k.segarTil = k.now().Add(k.ttl)
	return nil
}

// publicKey menerjemahkan JWK menjadi kunci publik ECDSA.
//
// Lewat ParseUncompressedPublicKey, BUKAN dengan mengisi koordinat X dan Y
// langsung. Yang kedua tampak lebih sederhana dan menyembunyikan satu
// pemeriksaan yang menentukan: titik yang tidak berada pada kurva bukan kunci,
// dan menerimanya membuka serangan kurva tidak sah. ParseUncompressedPublicKey
// memeriksanya sendiri, dan tidak dapat dilupakan.
func (j jwk) publicKey() (*ecdsa.PublicKey, error) {
	curve, err := curveFor(j.Crv)
	if err != nil {
		return nil, err
	}

	x, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("koordinat x tidak dapat dibaca: %w", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(j.Y)
	if err != nil {
		return nil, fmt.Errorf("koordinat y tidak dapat dibaca: %w", err)
	}

	// Lebar tetap per kurva. RFC 7518 memang menuntut koordinat JWK ditulis
	// dengan lebar itu, tetapi menerima yang lebih pendek apa adanya akan
	// menggeser seluruh byte dan menghasilkan titik yang berbeda — kegagalan
	// yang muncul sebagai "tanda tangan tidak cocok" tanpa menyebut sebabnya.
	lebar := (curve.Params().BitSize + 7) / 8
	if len(x) > lebar || len(y) > lebar {
		return nil, fmt.Errorf("koordinat lebih panjang dari kurva %s", j.Crv)
	}

	titik := make([]byte, 1+2*lebar)
	titik[0] = 4 // bentuk tidak terkompresi
	copy(titik[1+lebar-len(x):1+lebar], x)
	copy(titik[1+2*lebar-len(y):], y)

	key, err := ecdsa.ParseUncompressedPublicKey(curve, titik)
	if err != nil {
		return nil, fmt.Errorf("kunci %s tidak sah: %w", j.Crv, err)
	}
	return key, nil
}
