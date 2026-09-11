# GONSU One — SDK Login (Go)

**Untuk tim yang membangun produk untuk dijual di GONSU One.**

SDK ini mengurus satu hal, dan hanya satu: membuktikan **siapa** orang yang
sedang masuk. Produk yang memutuskan orang itu menjadi apa di dalamnya, dan
produk yang menghitung kuotanya sendiri.

```
go get github.com/gonsutrijayautama/gonsu-one-sdk-go-auth
```

Nol dependency di luar standard library, dan module tersendiri — **terpisah dari
SDK lisensi**, karena keduanya berlawanan di tiga hal sekaligus:

| | lisensi | auth |
|---|---|---|
| saat GONSU tak terjangkau | WAJIB tetap bekerja | login baru mustahil |
| yang dibuktikan | sebuah lease | sesi seseorang |
| kapan dipanggil | terus-menerus | sekali, di titik login |

## Kenapa ini ada

Alur OIDC terlihat sederhana, dan **salahnya tidak terlihat**. Lupa
membandingkan `state`, lupa `nonce`, lupa memverifikasi `aud`, lupa memeriksa
tenant — login tetap berhasil, pengguna tetap masuk, dan tidak ada yang gagal
sampai ada yang memanfaatkannya.

Kode dengan sifat seperti itu tidak boleh ditulis ulang di setiap produk.

## Nilainya datang dari GONSU

Produk tidak menyusun satu pun sendiri:

| mode | dari mana |
|---|---|
| cloud | environment aplikasi: `GONSU_OIDC_ISSUER`, `GONSU_OIDC_CLIENT_ID`, `GONSU_OIDC_CLIENT_SECRET`, `GONSU_OIDC_REDIRECT_URI` |
| self-host | agent: `GET http://agent:8099/v1/oidc` — **tanpa** `client_secret` |

Self-host memakai **client publik dengan PKCE**: rahasia yang ditaruh di mesin
yang administratornya pelanggan sendiri tidak melindungi apa pun dari pemilik
mesin itu.

## Pemakaian

```go
client, err := gonsuauth.New(gonsuauth.Options{
    Issuer:       os.Getenv("GONSU_OIDC_ISSUER"),
    ClientID:     os.Getenv("GONSU_OIDC_CLIENT_ID"),
    ClientSecret: os.Getenv("GONSU_OIDC_CLIENT_SECRET"), // kosong pada self-host
    RedirectURI:  os.Getenv("GONSU_OIDC_REDIRECT_URI"),
})
```

**Mulai login.** Simpan `pending` pada sesi sementara di sisi Anda — cookie
bertanda tangan, atau penyimpanan sesi apa pun. Menyimpannya di tempat yang
dapat dibaca atau ditulis pihak lain membuang seluruh gunanya.

```go
authorizeURL, pending, err := client.StartLogin(ctx)
// simpan pending, lalu arahkan pengguna ke authorizeURL
```

**Selesaikan login.**

```go
claims, err := client.HandleCallback(ctx, pending, r.URL.Query().Get("state"),
                                     r.URL.Query().Get("code"))
```

Yang diperiksa di dalamnya, dan semuanya wajib: `state`, tanda tangan, penerbit,
penerima, masa berlaku, waktu terbit, dan `nonce`.

**Pastikan orangnya memang diberi akses di sini.** Wajib, dan tidak dapat
dilewati diam-diam:

```go
err := gonsuauth.EnsureGranted(ctx, login.Claims, func(ctx context.Context, sub string) (bool, error) {
    return db.UserExistsByExternalSubject(ctx, sub)
})
```

Pemasangan self-host berbagi satu penyedia identitas dengan seluruh pelanggan
lain, sehingga token yang **sah menurut tanda tangan** dapat datang dari
pemasangan mana pun.

Yang dicocokkan adalah **tabel pengguna Anda sendiri**, bukan klaim di dalam
token — klaim itu tidak ada, karena GONSU tidak pernah membuat organization di
penyedia identitas. Dan tabel Anda lebih kuat: ia catatan Anda sendiri tentang
siapa yang benar-benar diberi akses oleh admin Anda.

> **JANGAN membuat pengguna baru dari `sub` yang tidak dikenal.** JIT
> shadow-user creation menghapus seluruh pemeriksaan ini: orang dari pemasangan
> lain akan dibuatkan akun alih-alih ditolak, dan tidak ada satu pun gejala
> sampai ada yang melihat data yang bukan miliknya.
>
> Pengguna lahir dari layar "beri akses login" di dalam produk Anda, bukan dari
> login pertama.

Kalau Anda tidak menyebutkan cara mencarinya, `EnsureGranted` mengembalikan
**galat** — bukan lulus.

## Sesudah login: sesi milik produk

`HandleCallback` mengembalikan `Login`:

```go
login.Claims       // siapa orangnya
login.IDToken      // untuk id_token_hint saat keluar
login.Session      // bahan pemeriksaan berkala — SIMPAN bersama sesi Anda
```

Petakan `login.Claims.Subject` ke pengguna lokal Anda, lalu terbitkan cookie
sesi Anda sendiri. **Jangan memvalidasi token GONSU pada setiap request** —
produk akan mati setiap kali GONSU sesaat tidak terjangkau.

Tabel pengguna lokal: `external_subject`, `tenant_id`, `application_role`, tanpa
password hash. Kuncinya `sub`, bukan email — email berubah, `sub` tidak.

## Pencabutan harus menjangkau sesi yang sudah berjalan

Tanpa ini, **orang yang di-offboard kemarin masih bekerja hari ini**: sesi
terbit sekali di titik login dan tidak pernah menanyakan ulang.

Panggil `VerifySession` pada permintaan yang masuk — ia murah, dan hanya
menyentuh jaringan ketika memang sudah waktunya:

```go
state, err := client.VerifySession(ctx, state)
if errors.Is(err, gonsuauth.ErrSessionExpired) {
    // matikan sesi produk, arahkan ke login lagi
}
// SIMPAN state yang dikembalikan: refresh token dapat dirotasi
```

Tiga keadaan, dan yang membedakannya bukan hasil melainkan **sebab**:

| | |
|---|---|
| belum waktunya | lanjut, tanpa menyentuh jaringan |
| GONSU menjawab | lanjut, waktunya disegarkan |
| GONSU **menolak** | mati seketika — masa tenggang tidak berlaku |
| GONSU **tak terjangkau** | lanjut selama masih dalam masa tenggang |

Perbedaan antara "menolak" dan "tak terjangkau" adalah inti seluruh mekanisme
ini. Menyamakannya berarti gangguan jaringan lima menit mengeluarkan setiap
orang di setiap pelanggan sekaligus — atau, ke arah sebaliknya, orang yang
dicabut tetap bekerja selama jaringannya kebetulan buruk.

Angkanya datang dari GONSU (`GONSU_OIDC_RECHECK_SECONDS`,
`GONSU_OIDC_OFFLINE_GRACE_SECONDS`), bawaannya **15 menit** dan **12 jam** —
satu shift kerja.

**Scope `offline_access` wajib.** Tanpanya penyedia identitas tidak menerbitkan
refresh token, dan pencabutan tidak akan pernah menjangkau sesi mana pun. Ia
sudah termasuk pada scope bawaan; produk yang menyetel `Scopes` sendiri memikul
akibatnya.

## Sandi: tautan, bukan formulir

```go
client.ForgotPasswordURL()
client.ChangePasswordURL()
client.LogoutURL(ctx, idToken, "https://aplikasi-anda/")
```

Layar sandi **di dalam produk** melatih pengguna mengetik sandi GONSU-nya di
domain produk. Satu-satunya hal yang membuat SSO bernilai adalah pengguna dapat
melihat bahwa yang meminta sandinya benar-benar alamat GONSU; begitu kebiasaan
itu hilang, memalsukan layar login tinggal menyalin tampilannya.

## Kontrak yang dibekukan

`sdk/contract/auth-contract.json` memuat vektor uji yang dapat dijalankan SDK
bahasa mana pun — dan bagian paling berharganya adalah token yang harus
**ditolak**. SDK auth bahasa baru menjadikannya test: "buat berkas ini hijau".
