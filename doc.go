// Package gonsuauth adalah SDK login untuk produk yang dijual GONSU One.
//
// Ia mengurus satu hal, dan hanya satu: membuktikan SIAPA orang yang sedang
// masuk. Produk yang memutuskan orang itu menjadi apa di dalamnya, dan produk
// yang menghitung kuotanya sendiri.
//
// # Kenapa ini ada
//
// Alur OIDC terlihat sederhana dan salahnya TIDAK TERLIHAT. Lupa membandingkan
// `state`, lupa `nonce`, lupa memverifikasi `aud`, lupa memeriksa tenant —
// login tetap berhasil, pengguna tetap masuk, dan tidak ada yang gagal sampai
// ada yang memanfaatkannya. Kode dengan sifat seperti itu tidak boleh ditulis
// ulang di setiap produk.
//
// # TERPISAH dari SDK lisensi, dan itu keputusan
//
// Keduanya berlawanan di tiga hal sekaligus:
//
//   - saat GONSU tak terjangkau: lisensi WAJIB tetap bekerja, login baru
//     mustahil;
//   - dependency: lisensi berjanji nol, auth butuh verifikasi JWT;
//   - yang dibuktikan: lisensi membuktikan sebuah lease, auth membuktikan sesi
//     seseorang.
//
// Memaksa produk yang hanya butuh lisensi ikut menarik dependency auth akan
// mengingkari janji nol dependency.
//
// Package ini tetap NOL DEPENDENCY di luar standard library — janji yang sama,
// dipenuhi dengan cara yang sama: verifikasi JWT ditulis di sini, bukan
// ditarik. Yang dibutuhkannya hanya ECDSA dan SHA-2, dan keduanya ada di
// standard library.
//
// # Yang TIDAK ada di sini
//
// Reset dan lupa sandi. Sandi berada di penyedia identitas, dan layar sandi di
// dalam produk MELATIH pengguna mengetik sandi GONSU-nya di domain produk —
// begitu kebiasaan itu ada, memalsukan layar login tinggal menyalin
// tampilannya. Yang disediakan hanyalah tautan.
package gonsuauth
