package gonsuauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// metadata adalah bagian dokumen discovery yang benar-benar dipakai.
type metadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	EndSessionEndpoint    string   `json:"end_session_endpoint"`
	SigningAlgs           []string `json:"id_token_signing_alg_values_supported"`
	ChallengeMethods      []string `json:"code_challenge_methods_supported"`
}

// discover membaca dokumen discovery lalu MEMERIKSANYA terhadap issuer yang
// dikonfigurasi.
//
// Pemeriksaan itu bukan formalitas. `iss` di dalam token dibandingkan dengan
// nilai yang dikonfigurasi, sedangkan endpoint diambil dari dokumen ini —
// membiarkan keduanya berbeda berarti produk menukar code di satu tempat dan
// mempercayai token yang mengaku dari tempat lain.
//
// Alamat dokumennya BOLEH berbeda dari issuer, dan itu keadaan yang nyata:
// pemasangan di dalam cluster menempuh alamat dalam, sedangkan `iss` yang
// ditandatangani harus alamat publik yang juga dapat dibuka browser. Yang tidak
// boleh berbeda adalah `issuer` DI DALAM dokumen.
func discover(ctx context.Context, client *http.Client, discoveryURL, issuer string) (metadata, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return metadata{}, fmt.Errorf("menyiapkan permintaan discovery: %w", err)
	}

	response, err := client.Do(request)
	if err != nil {
		return metadata{}, fmt.Errorf("mengambil dokumen discovery: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return metadata{}, fmt.Errorf("discovery dijawab %d", response.StatusCode)
	}

	var doc metadata
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&doc); err != nil {
		return metadata{}, fmt.Errorf("dokumen discovery tidak dapat dibaca: %w", err)
	}

	if doc.Issuer != issuer {
		return metadata{}, fmt.Errorf(
			"issuer pada dokumen discovery %q tidak sama dengan yang dikonfigurasi %q",
			doc.Issuer, issuer)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" || doc.JWKSURI == "" {
		return metadata{}, fmt.Errorf("dokumen discovery tidak lengkap")
	}
	if len(doc.ChallengeMethods) > 0 && !contains(doc.ChallengeMethods, challengeMethod) {
		// PKCE bukan tambahan yang boleh dilewati di sini: client publik
		// bersandar padanya sepenuhnya. Penyedia identitas yang
		// tidak mendukungnya berarti konfigurasinya salah, bukan berarti
		// login boleh dilanjutkan tanpanya.
		return metadata{}, fmt.Errorf("penyedia identitas tidak mendukung PKCE %s", challengeMethod)
	}
	return doc, nil
}

// defaultDiscoveryURL menyusun alamat dokumen discovery dari issuer.
func defaultDiscoveryURL(issuer string) string {
	return strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
}

func contains(daftar []string, nilai string) bool {
	for _, item := range daftar {
		if item == nilai {
			return true
		}
	}
	return false
}
