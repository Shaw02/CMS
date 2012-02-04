+-----------------------------------------------------------------------------
| タイトル | ＣＭＳ（暗号メッセージ構文）対応　暗号／復号ソフトウェア
|ファイル名| CMS190.ZIP
| カテゴリ | Win32 Command-line User Interface (コマンドラインプログラム)
| 動作機種 | SSE2（SIMD）命令に対応したCPU
|前提ソフト| Windows 2000 SP4, Windows XP, Windows Vista, Windows Server 2003
| 圧縮方式 | zip
|転載の可否| 先ずは、連絡ください。
|  備  考  | 質問等は出来ればメールでお願いします。
+-----------------------------------------------------------------------------

単一ファイルに対して、暗号・復号を行うソフトウェアです。
暗号メッセージ構文(Cryptographic Message Syntax:CMS)（RFC.5652）に準拠しています。
又、AES暗号処理では、SIMD（SSE2）命令セットを使用し、高速に処理します。

※CUI（コマンドライン・ユーザー・インターフェイス）アプリケーションです。
　製品版のVisual Studio.netを買う気が無いので、GUIは今のところ考えてません。

※暗号のみ対応です。電子署名（Signed-data Type）等には対応していません。



■対応アルゴリズム
━━━━━━━━━━━━
《暗号関数》
・DES-CBC		※政府承認暗号から削除されました。
・DES-3EDE-CBC		※推奨されません。
・AES-128-CBC
・AES-192-CBC
・AES-256-CBC

《鍵導出関数》		（※パスワード文字列から、暗号鍵を計算する関数です。）
・PBKDF2

《鍵付きハッシュ関数》	（※"PBKDF2"で使う、攪乱関数です。）
・HMAC-SHA-1
・HMAC-SHA-224
・HMAC-SHA-256

《疑似乱数》		（※セッション鍵や、初期化ベクタIVに用います。）
・Mersenne Twister ＋ SHA-256



■対応ファイル
━━━━━━━━━━━━
　　【暗号文ファイル（*.p7）】
	PKCS#7 Cryptographic Message Syntax (CMS)
	・Enveloped-data Type (鍵導出に対応)
	・Encrypted-data Type
　　【暗号鍵ファイル（*.key）】
	PKCS#8 Public-Key Cryptography Standards
	Private-Key Information Syntax Specification Version 1.2
	※対称鍵における秘密鍵用の規格ですが、共通鍵を格納しています。
	※Encrypted-data Typeのファイルを処理する時に用います。


								Ｓ．Ｗ．

========================================================================
●連絡先
・E-mail	sha_w@nifty.com
・URL		http://shaw.la.coocan.jp/
・mixi		http://mixi.jp/show_profile.pl?id=16558
========================================================================

製作のファイルは【CMS190.ZIP】です。
