package gonsuauth

import (
	"context"
	"errors"
	"fmt"
)

// ErrNotGranted berarti token sah, tetapi orangnya tidak pernah diberi akses ke
// pemasangan ini.
//
// Bukan kegagalan autentikasi — orangnya memang terbukti. Yang tidak ada adalah
// haknya berada di sini.
var ErrNotGranted = errors.New("orang ini tidak diberi akses ke pemasangan ini")

// ErrLookupMissing berarti produk tidak menyebutkan cara mencari penggunanya.
//
// Dikembalikan sebagai GALAT, bukan dilewati diam-diam. Aturannya menyatakan
// pemeriksaan ini WAJIB: tanpanya, jaminan bahwa tenant A tidak dapat mengakses
// resource tenant B bergantung sepenuhnya pada penyedia identitas
// menerbitkan audience yang tepat, dan satu salah konfigurasi di sana tidak
// akan tertangkap di mana pun.
//
// Melewatkannya diam-diam berarti produk berjalan bertahun-tahun dengan
// pemeriksaan yang tidak pernah berjalan, dan tidak ada satu pun gejala sampai
// ada yang melihat data yang bukan miliknya.
var ErrLookupMissing = errors.New("cara mencari pengguna tidak disebutkan")

// SubjectLookup menjawab apakah sebuah `sub` sudah pernah diberi akses oleh
// pemasangan ini.
//
// Diimplementasikan produk terhadap tabel penggunanya sendiri — baris yang
// menyimpan `external_subject`. Ketiadaan baris BUKAN galat; ia
// jawaban "belum pernah diberi akses".
type SubjectLookup func(ctx context.Context, subject string) (bool, error)

// EnsureGranted menolak orang yang tidak pernah diberi akses ke pemasangan ini.
//
// # Kenapa tabel produk, bukan klaim di dalam token
//
// Karena klaim itu TIDAK ADA. Diperiksa terhadap penyedia identitas yang
// berjalan: nol organization, `custom_data` kosong, nol keanggotaan — GONSU
// memang tidak pernah membuat organization di sana. Memeriksa klaim tenant
// berarti menolak setiap orang.
//
// Menciptakannya menuntut GONSU mencerminkan keanggotaan ke penyedia identitas,
// yaitu sumber kebenaran KEDUA untuk sesuatu yang sudah dimiliki
// `organization_memberships` di GONSU. Proyeksi seperti itu basi pada perubahan
// keanggotaan pertama, dan data otorisasi yang basi salah tanpa gejala.
//
// Yang dipakai sebagai gantinya lebih kuat: produk membuat SETIAP penggunanya
// sendiri lewat `/license/v1/identities`, dan menyimpan `external_subject`-nya.
// Sebuah `sub` yang tidak dikenalnya berarti orang yang tidak pernah diberi
// akses oleh pemasangan ini — catatan produk SENDIRI, bukan klaim yang
// diterbitkan pihak lain.
//
// # Yang WAJIB dijaga produk
//
// JANGAN membuat pengguna baru dari `sub` yang tidak dikenal. JIT shadow-user
// creation terlihat praktis, dan pada jalur ini ia
// MENGHAPUS seluruh pemeriksaannya: orang dari pemasangan lain akan dibuatkan
// akun alih-alih ditolak, dan tidak ada satu pun gejala sampai ada yang melihat
// data yang bukan miliknya.
//
// Pengguna lahir dari layar "beri akses login" di dalam produk, bukan dari
// login pertama.
func EnsureGranted(ctx context.Context, claims Claims, granted SubjectLookup) error {
	if granted == nil {
		return ErrLookupMissing
	}
	if claims.Subject == "" {
		return fmt.Errorf("%w: token tanpa subject", ErrNotGranted)
	}

	ada, err := granted(ctx, claims.Subject)
	if err != nil {
		// Kegagalan MENCARI bukan jawaban "tidak berhak". Memperlakukannya
		// begitu berarti database yang sesaat tidak dapat dihubungi
		// mengeluarkan setiap orang sekaligus.
		return fmt.Errorf("mencari pengguna %s: %w", claims.Subject, err)
	}
	if !ada {
		return fmt.Errorf("%w: %s", ErrNotGranted, claims.Subject)
	}
	return nil
}
