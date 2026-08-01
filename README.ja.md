# hwvault

> **Hardware-bound credential vault for Go** — ハードウェアに紐付けた認証情報の暗号化保管ライブラリ

[![Go Reference](https://pkg.go.dev/badge/github.com/Takahiro3D/hwvault.svg)](https://pkg.go.dev/github.com/Takahiro3D/hwvault)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> 📐 設計思想・脅威モデル・アーキテクチャの詳細は [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) を参照してください。

---

## 概要

`hwvault` は、Go製のローカルCLI・デスクトップツール向けに、認証情報（APIキー、パスワード等）を **実行マシンのハードウェア情報に紐付けて暗号化保管** するライブラリです。

暗号化されたファイルが別のPCにコピー・流出しても、そのマシンでは復号できません（**ノードロック**）。

開発者はセキュリティの実装詳細を意識することなく、`Save` / `Load` の2つのAPIを呼ぶだけで安全な認証情報保管を実現できます。

---

## 特徴

- 🔒 **ノードロック暗号化** — HW固有IDを鍵材料とし、別PCでの復号を防止
- 🛡️ **AES-256-GCM** — 改ざん検知付きの業界標準暗号化方式を採用
- 📁 **パーミッション自動制御** — 保存ファイルに `0600`、ディレクトリに `0700` を強制
- 🖥️ **クロスプラットフォーム** — Linux / Windows 対応
- ✅ **Secure by Default** — 安全でない使い方をAPIレベルで排除

---

## インストール

```bash
go get github.com/Takahiro3D/hwvault
```

---

## クイックスタート

```go
package main

import (
    "fmt"
    "log"
    "os"
    "path/filepath"
    "github.com/Takahiro3D/hwvault"
)

const appSalt = "myapp-v1-credential-salt"

func main() {
    // hwvault はパス解決（"~" 展開等）を行いません。
    // 呼び出し側で os.UserHomeDir() 等を使ってパスを解決してください。
    home, err := os.UserHomeDir()
    if err != nil {
        log.Fatal(err)
    }
    vaultPath := filepath.Join(home, ".myapp", "credentials.vault")

    // 認証情報を暗号化してファイルに保存
    err = hwvault.Save(vaultPath, "my-secret-api-key", appSalt)
    if err != nil {
        log.Fatal(err)
    }

    // ファイルから読み込んで復号
    secret, err := hwvault.Load(vaultPath, appSalt)
    if err != nil {
        // HW変更・ファイル破損時はここに来る → ユーザーに再ログインを促す
        log.Fatal(err)
    }

    fmt.Println("取得した認証情報:", secret)
}
```

> ℹ️ **注意:** `hwvault` は `~` 展開などのパス解決を行いません。
> 絶対パス（または解決済みのパス）を渡すのは呼び出し側の責任です。


---

## API リファレンス

### 高レベルAPI（推奨）

ファイル操作・パーミッション管理・暗号復号を一括処理します。

```go
// Save は plainText を暗号化し、filePath にパーミッション 0600 で保存します。
// filePath の親ディレクトリが存在しない場合、パーミッション 0700 で自動生成します。
func Save(filePath string, plainText string, salt string) error

// Load は filePath のファイルを読み込み、復号した文字列を返します。
// 別PCへのファイルコピー後や、HW構成変更後は復号に失敗します。
func Load(filePath string, salt string) (string, error)
```

> ℹ️ **相対パスに関する注意:** `hwvault` は `filePath` に対して特別な処理を行いません。
> 相対パスを渡した場合、Go標準（`os` パッケージ）の挙動に従い、カレントディレクトリ基準で解決されます。

> ℹ️ **パーミッション検証に関する注意:** `Load` 実行時、ファイルのパーミッションが `0600` でない場合、`hwvault` はエラーにはせず警告を出力します（バックアップから復元したファイル等の正当な利用ケースを妨げないため）。

> ⚠️ **Windows環境に関する注意:** Windows（NTFS）にはUnix系のようなパーミッションビットのモデルが存在しません。Windows上の`os.Chmod`/`FileInfo.Mode()`は読み取り専用属性のON/OFFしか制御できないため、保存されたファイルは`0600`ではなく`0666`（書き込み可）として観測されます。これはhwvaultの欠陥ではなく、GoランタイムおよびNTFSの制約による既知の仕様です。詳細は[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)を参照してください。


### 低レベルAPI


ファイルを使わず、メモリ上での暗号化/復号のみを行います。

```go
// Encrypt は plainText を HW情報+salt で暗号化し、バイト列を返します。
func Encrypt(plainText string, salt string) ([]byte, error)

// Decrypt は暗号化されたバイト列を復号し、文字列を返します。
func Decrypt(cipherData []byte, salt string) (string, error)
```

---

## `salt`（アプリ固有ソルト）について

`salt` はアプリケーションごとに固定の文字列を指定してください。

- 同じHWでも、`salt` が異なれば別の鍵が生成されます。
- 異なるアプリ間での暗号化データの流用を防ぐ役割を持ちます。
- **`salt` はソースコードや設定ファイルに埋め込んで構いません。** 秘密情報ではなく、アプリの識別子として機能します。
- ただし、一度決めた `salt` を変更すると既存の保存データが復号できなくなります。

---

## エラーハンドリング

```go
secret, err := hwvault.Load(filePath, appSalt)
if err != nil {
    switch {
    case errors.Is(err, hwvault.ErrDecryptionFailed):
        // HW変更・別PCへのコピー・ファイル破損のいずれか
        // → 保存データを削除し、ユーザーに再ログインを促す
        promptReLogin()
    case errors.Is(err, hwvault.ErrHWIDUnavailable):
        // HW ID の取得に失敗（権限不足・非対応環境等）
        log.Fatal("このマシンはhwvaultに対応していません:", err)
    case errors.Is(err, hwvault.ErrUnsupportedVersion):
        // 新しい/非互換バージョンのhwvaultで作成されたファイル
        // → 復号失敗と同様に扱い、ユーザーに再ログインを促す
        promptReLogin()
    default:
        log.Fatal("予期しないエラー:", err)
    }
}
```

| エラー | 発生条件 | 推奨対応 |
|---|---|---|
| `ErrDecryptionFailed` | 別PCへのコピー、HW変更、ファイル破損 | 保存データ削除 → 再ログイン促進 |
| `ErrHWIDUnavailable` | HW ID取得失敗（権限不足・非対応環境） | 起動時チェックでユーザーに通知 |
| `ErrInvalidData` | 保存データのフォーマット不正 | 保存データ削除 → 再ログイン促進 |
| `ErrUnsupportedVersion` | 保存データの `version` バイトが現バージョンの hwvault で非対応 | 保存データ削除 → 再ログイン促進 |

> ℹ️ **並行処理に関する注意:** `hwvault` は単一プロセスでの一時的な利用（CLIのログインフロー等）を想定しています。
> 複数プロセス・複数goroutineから同一ファイルへ同時に `Save`/`Load` することはサポートしていません。


---

## ⚠️ セキュリティ境界線（重要）

**このライブラリが守るもの・守らないものを明確に理解した上でご利用ください。**

### ✅ 守るもの（In-Scope）

| 脅威 | 対策 |
|---|---|
| 暗号化ファイルの別PCへのコピー・流出による不正利用 | HW固有IDを鍵材料とするため、別マシンでは復号不可 |
| 不適切なファイルパーミッションによる同一PC内他ユーザーからの読み取り | `0600` / `0700` を強制適用 |
| 保存データの改ざん | AES-256-GCM の認証タグにより検知・復号失敗 |

### ❌ 守らないもの（Out-of-Scope）

| 脅威 | 理由・補足 |
|---|---|
| **同一PC上で動作するマルウェア・悪意あるプロセスによる復号** | 同じHWで動作するプロセスは原理的に同じ鍵を生成できるため防御不可。EDR・アンチウイルス等のPC防衛（第1層）に委ねる。 |
| **物理的なメモリダンプ・コールドブート攻撃** | 本ライブラリのスコープ外。 |
| **`salt` の漏洩による鍵の推測** | `salt` 単体では鍵を生成できない（HW IDが必要）。ただし `salt` の管理はアプリ側の責任。 |
| **HW IDのスプーフィング（仮想マシン等での偽装）** | VM環境でのHW ID偽装には対応しない。VM利用時の挙動はアプリ側で考慮すること。 |

> **多層防御における位置づけ:**
> ```
> 第1層: EDR / アンチウイルス（マルウェア対策）
> 第2層: hwvault（ファイル流出時の不正利用防止）  ← ここ
> 第3層: アプリ側の認証・認可ロジック
> ```

---

## 技術仕様

| 項目 | 仕様 |
|---|---|
| 暗号化方式 | AES-256-GCM |
| 鍵導出 | HMAC-SHA256(HW_ID + salt) |
| HW ID取得（Linux） | `/etc/machine-id`（[`machineid`](https://github.com/denisbrodbeck/machineid) パッケージ経由） |
| HW ID取得（Windows） | `MachineGuid`（レジストリ、[`machineid`](https://github.com/denisbrodbeck/machineid) パッケージ経由） |
| Nonce | 12バイト（`crypto/rand` で毎回生成） |
| 保存フォーマット | `version(1byte) \| nonce(12byte) \| ciphertext+tag` |
| ファイルパーミッション | `0600`（ファイル）/ `0700`（ディレクトリ） |

> ⚠️ **コンテナ（Docker等）環境に関する注意:** hwvaultは [`machineid`](https://github.com/denisbrodbeck/machineid) パッケージによるID解決（Linuxでは `/etc/machine-id`）に依存します。コンテナ環境では、このファイルの存在・値はhwvaultによって保証されません。コンテナランタイムやイメージによっては、ファイルが存在しない、コンテナインスタンス間で異なる、コンテナ再作成時に変化・維持されるなどの挙動になる可能性があります。本ライブラリは主にオンプレミス・ベアメタルまたはVM環境での利用を想定して設計されており、コンテナ固有の動作は正式に検証していません。

### `version` フィールドの運用方針


`version` バイトは保存ファイルのフォーマット世代を表し、ライブラリのSemVerと以下のように対応します。

| ライブラリSemVerの変更 | 意味 | `version` バイトへの影響 |
|---|---|---|
| **メジャー**（例: v1→v2） | API互換なし | 新フォーマットが導入される場合あり |
| **マイナー**（例: v1.1→v1.2） | API互換あり、既存vaultファイルの再生成が必要 | **インクリメント**（例: `0x01`→`0x02`） |
| **パッチ**（例: v1.1.0→v1.1.1） | バグ修正等、フォーマット変更なし | 変更なし |

`Save` は常に現在サポートする最新の `version` を書き込みます。`Load` は未知の `version`（旧世代を含む）を検出した場合、`ErrUnsupportedVersion` を返します。呼び出し側はこれを `ErrDecryptionFailed` と同様に扱ってください（保存データ削除 → 再ログイン促進）。実装をシンプルに保つため、旧フォーマットの後方互換読み込みは意図的にサポートしません。

### アトミックな保存処理

`Save` は `filePath` と同じディレクトリに一時ファイル（例: `filePath + ".tmp"`）を作成し、`os.Rename` でアトミックに置き換えます。これにより、書き込み中にプロセスがクラッシュしたりディスクフルになった場合でも、既存の（有効な）vaultファイルが破損・消失することはなく、新しい書き込みの失敗として処理されます。

---


## 類似ライブラリとの比較：`go-keyring`

[`go-keyring`](https://github.com/zalando/go-keyring) は、OS標準の資格情報マネージャー（macOS Keychain・Windows Credential Manager・Linux Secret Service）をバックエンドとして利用するライブラリです。

### 比較表

| 項目 | `hwvault` | `go-keyring` |
|---|---|---|
| **保管バックエンド** | HW固有IDで暗号化したファイル（任意のパス） | OS標準の資格情報マネージャー |
| **ノードロック（別PCでの復号防止）** | ✅ HW IDが異なれば復号不可 | ✅ OS資格情報ストアに紐付くため別PCでは取得不可 |
| **ヘッドレスLinux対応** | ✅ デーモン不要・ファイルのみで動作 | ❌ `gnome-keyring` 等のデーモンが必要なケースがある |
| **CI/CDパイプライン・サーバー環境** | ✅ 動作可能 | ⚠️ 環境依存（Secret Serviceが使えない場合がある） |
| **保管場所の可搬性** | ✅ ファイルパスを自由に指定可能（バックアップ・移行が容易） | ❌ OS管理のストアに保存されるため場所を制御しにくい |
| **macOS対応** | ⚠️ 未検証（理論上は動作可能） | ✅ Keychain経由で安定動作 |
| **Windows対応** | ✅ 対応 | ✅ Credential Manager経由で対応 |
| **外部デーモン・サービス依存** | ❌ なし（依存ゼロ） | ⚠️ OS資格情報サービスへの依存あり |
| **暗号化の透明性** | ✅ 実装がコード上で完全に把握可能 | ❌ OSの実装に依存（ブラックボックス） |
| **ファイルパーミッション制御** | ✅ `0600` / `0700` を強制 | — （OS管理のため不要） |


### どちらを選ぶべきか

**`hwvault` が適しているケース:**

- ヘッドレスなLinuxサーバー・CI/CD環境でも動作させたい
- 保管ファイルの場所を自分で管理・バックアップしたい
- OS資格情報マネージャーへの依存を避けたい
- 暗号化の実装をコードレベルで把握・監査したい
- 非エンジニアユーザー向けのローカルツールで、環境差異を吸収したい

**`go-keyring` が適しているケース:**

- macOSを主要プラットフォームとして安定した資格情報管理が必要
- OS標準の資格情報マネージャーとの統合が求められる（企業ポリシー等）
- GUIアプリケーションでOSのロック画面連動が必要
- デスクトップ環境が保証されており、Secret Serviceが利用可能

---

## HW変更時の運用

PCのパーツ交換・OS再インストール等でHW IDが変化した場合、既存の保存データは復号できなくなります。

**推奨フロー:**

```
復号失敗 (ErrDecryptionFailed)
    ↓
古い vault ファイルを削除
    ↓
ユーザーに再ログイン（パスワード再入力）を促す
    ↓
新しいHW IDで再暗号化・保存
```

これは仕様上の正常な動作です。アプリ側でこのフローを実装してください。

---

## 対応環境

| OS | 対応状況 |
|---|---|
| Linux | ✅ 対応 |
| Windows | ✅ 対応 |
| macOS | ⚠️ 未検証 |

> **macOSについて:** 内部で利用する [`machineid`](https://github.com/denisbrodbeck/machineid) パッケージはmacOS（`IOPlatformUUID`）に対応しているため、理論上は動作するはずです。しかし、動作検証にはmacOS CI runnerが必要となり、現時点では維持コストが高いと判断し、実際の動作検証は行っていません。

---


## ライセンス

MIT License — 詳細は [LICENSE](LICENSE) を参照してください。
