package gonsuauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
)

// ErrInvalidToken berarti token tidak dapat dipercaya. Sebabnya disebutkan di
// pesan; yang dijadikan pegangan program adalah errors.Is terhadap sentinel ini.
var ErrInvalidToken = errors.New("id_token tidak sah")

// header adalah bagian pertama JWT.
type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// Claims adalah isi id_token yang sudah TERVERIFIKASI.
//
// Hanya klaim yang benar-benar dipakai yang diberi nama. Sisanya tetap
// tersedia lewat Raw — produk yang membutuhkan klaim khusus penyedia
// identitasnya tidak boleh terpaksa menunggu SDK menambahkannya.
type Claims struct {
	Issuer   string
	Subject  string
	Audience []string
	Nonce    string
	Email    string
	Name     string
	// ExpiresAt dan IssuedAt dalam detik epoch.
	ExpiresAt int64
	IssuedAt  int64
	// Raw memuat seluruh klaim apa adanya.
	Raw map[string]any
}

// parseSegments memecah JWT menjadi tiga bagiannya.
//
// Bentuknya diperiksa SEBELUM apa pun diurai: token dengan dua bagian adalah
// token tanpa tanda tangan, dan mengurainya lebih dulu berarti membaca isi yang
// belum terbukti milik siapa pun.
func parseSegments(token string) (headerRaw, payloadRaw, signature []byte, signed string, err error) {
	bagian := strings.Split(token, ".")
	if len(bagian) != 3 {
		return nil, nil, nil, "", fmt.Errorf("%w: bentuknya bukan JWT", ErrInvalidToken)
	}

	headerRaw, err = base64.RawURLEncoding.DecodeString(bagian[0])
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("%w: header tidak dapat dibaca", ErrInvalidToken)
	}
	payloadRaw, err = base64.RawURLEncoding.DecodeString(bagian[1])
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("%w: payload tidak dapat dibaca", ErrInvalidToken)
	}
	signature, err = base64.RawURLEncoding.DecodeString(bagian[2])
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("%w: tanda tangan tidak dapat dibaca", ErrInvalidToken)
	}
	return headerRaw, payloadRaw, signature, bagian[0] + "." + bagian[1], nil
}

// verifyECDSA memeriksa tanda tangan ES256/ES384/ES512.
//
// Tanda tangan JWS berbentuk R‖S dengan panjang TETAP per kurva — bukan DER.
// Menerima panjang lain adalah lubang: implementasi yang memakai ParseECDSA
// atas DER dapat menerima tanda tangan yang di-padding berbeda namun bernilai
// sama, dan perbedaan itu cukup untuk menggagalkan pencocokan token yang
// seharusnya unik.
func verifyECDSA(key *ecdsa.PublicKey, alg, signed string, signature []byte) error {
	var digest hash.Hash
	var ukuran int
	switch alg {
	case "ES256":
		digest, ukuran = sha256.New(), 32
	case "ES384":
		digest, ukuran = sha512.New384(), 48
	case "ES512":
		digest, ukuran = sha512.New(), 66
	default:
		return fmt.Errorf("%w: algoritma %q tidak didukung", ErrInvalidToken, alg)
	}

	if len(signature) != 2*ukuran {
		return fmt.Errorf("%w: panjang tanda tangan %d, seharusnya %d",
			ErrInvalidToken, len(signature), 2*ukuran)
	}

	digest.Write([]byte(signed))
	r := new(big.Int).SetBytes(signature[:ukuran])
	s := new(big.Int).SetBytes(signature[ukuran:])
	if !ecdsa.Verify(key, digest.Sum(nil), r, s) {
		return fmt.Errorf("%w: tanda tangan tidak cocok", ErrInvalidToken)
	}
	return nil
}

// curveFor memetakan nama kurva JWK ke kurva Go.
func curveFor(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("%w: kurva %q tidak didukung", ErrInvalidToken, crv)
	}
}

// decodeClaims membaca payload menjadi Claims.
//
// `aud` sengaja diterima dalam DUA bentuk. Spesifikasi JWT mengizinkan string
// tunggal maupun daftar, dan implementasi yang hanya menerima salah satunya
// akan gagal pada penyedia identitas yang memakai bentuk lain — kegagalan yang
// muncul sebagai "login tidak bekerja" tanpa menyebut sebabnya.
func decodeClaims(payload []byte) (Claims, error) {
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return Claims{}, fmt.Errorf("%w: payload bukan JSON", ErrInvalidToken)
	}

	claims := Claims{Raw: raw}
	claims.Issuer, _ = raw["iss"].(string)
	claims.Subject, _ = raw["sub"].(string)
	claims.Nonce, _ = raw["nonce"].(string)
	claims.Email, _ = raw["email"].(string)
	claims.Name, _ = raw["name"].(string)

	switch aud := raw["aud"].(type) {
	case string:
		claims.Audience = []string{aud}
	case []any:
		for _, item := range aud {
			if teks, ok := item.(string); ok {
				claims.Audience = append(claims.Audience, teks)
			}
		}
	}

	if exp, ok := raw["exp"].(float64); ok {
		claims.ExpiresAt = int64(exp)
	}
	if iat, ok := raw["iat"].(float64); ok {
		claims.IssuedAt = int64(iat)
	}
	return claims, nil
}
