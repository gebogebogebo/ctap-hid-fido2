# CTAP2 お勉強メモ#9 - CTAP 2.1 PRE authenticatorCredentialManagement



# はじめに

これはCTAPのお勉強をしたメモです。
**WebAuthn(ウェブオースン)ではなく、CTAP(シータップ)であります。**

[WebAuthn Level2](https://www.w3.org/TR/webauthn-2/) が W3C Recommendation になりました！。 

今回はCTAP2.1の **authenticatorCredentialManagement** です。



- 教科書
  - [CTAP仕様 Client to Authenticator Protocol (CTAP) Proposed Standard, Review Draft, March 09, 2021](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html)

- 教材
	- [SoloKey](https://solokeys.com/)

- 復習
	- [CTAP2 お勉強メモ#1](https://qiita.com/gebo/items/d2ffbd4fcf7d75e21b63)
	- [CTAP2 お勉強メモ#2](https://qiita.com/gebo/items/e0bd197d607312dcf4fb)
	- [CTAP2 お勉強メモ#3](https://qiita.com/gebo/items/2cfc3202cd88a59b24ba)
	- [CTAP2 お勉強メモ#4](https://qiita.com/gebo/items/634aa39b0e08d8258682)
	- [CTAP2 お勉強メモ#5](https://qiita.com/gebo/items/84454583daeaf6711fd0)
	- [CTAP2 お勉強メモ#6](https://qiita.com/gebo/items/cfc6ceb1c7f9aa5fdad6)
	- [CTAP2 お勉強メモ#7](https://qiita.com/gebo/items/2c9d020c0768b95a01b0)
	- [CTAP2 お勉強メモ#8](https://qiita.com/gebo/items/f4dfedce907babb46241)

- 環境
	- Mac Os Big Sur
	- Visual Studio Code
		- Rust



## CTAP 2.1 PRE について

今世の中に出回っているセキュリティキーは既にCTAP2.1を実装しているものがありまして、 [authenticatorGetInfo](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#authenticatorGetInfo) で **FIDO_2_1_PRE** という version が採れるものがあります。<br>そのセキュリティキーを使って **authenticatorCredentialManagement** を検証しました。



## authenticatorCredentialManagement

[教科書 - 6.8 authenticatorCredentialManagement (0x0A)](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#authenticatorCredentialManagement)

authenticatorCredentialManagement は Residentkey で記録されたセキュリティキー内のクレデンシャルデータを管理するコマンドです。<br>サブコマンド形式になっています。

| subCommand Name                       | **subCommand Number** |                                            |
| ------------------------------------- | --------------------- | ------------------------------------------ |
| getCredsMetadata                      | 0x01                  | クレデンシャル数を取得する                 |
| enumerateRPsBegin                     | 0x02                  | RP情報を取得する                           |
| enumerateRPsGetNextRP                 | 0x03                  | RP情報を取得する                           |
| enumerateCredentialsBegin             | 0x04                  | クレデンシャルを取得する                   |
| enumerateCredentialsGetNextCredential | 0x05                  | クレデンシャルを取得する                   |
| deleteCredential                      | 0x06                  | クレデンシャルを削除する                   |
| updateUserInformation                 | 0x07                  | クレデンシャルのユーザーデータをUpdateする |



### getCredsMetadata

セキュリキーに記録可能なクレデンシャルの最大数と現在記録されているクレデンシャルの数を取得します。

subCommand (0x01) にgetCredsMetadata(0x01) を指定して、pinUvAuthProtocol(0x03)、pinUvAuthParam(0x04)を設定してCBORを投げると応答が返ってきます。



- getCredsMetadataでとれる情報
  - existingResidentCredentialsCount (0x01) : セキュリキーに記録可能なクレデンシャルの最大数
  - maxPossibleRemainingResidentCredentialsCount (0x02) : 現在記録されているクレデンシャルの数

私の持ってるキーだと

- existingResidentCredentialsCount = 2

- maxPossibleRemainingResidentCredentialsCount = 50

って感じで、ResidetKeyしてクレデンシャルを登録していくと existingResidentCredentialsCount が増えていく感じです。



#### pinUvAuthProtocol,pinUvAuthParam

authenticatorCredentialManagement の各サブコマンドにはpinUvAuthProtocol、pinUvAuthParamを指定する必要があります。これはPINの情報で、取得する情報がクレデンシャルなので当然といえば当然ですね。ただ生成シーケンスがかなりめんどくさいです。

##### pinUvAuthProtocol

PIN/UV Auth プロトコルを指定します。かんたんにいうとPINをどんなふうに暗号化しているかです。<br>仕様では  1 ([6.5.6. PIN/UV Auth Protocol One](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#pinProto1)) と 2 ([6.5.7. PIN/UV Auth Protocol Two](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#pinProto2)) がありまして。<br>どっちでもいいというわけではなくて、セキュリティキーに対して authenticatorGetInfo 投げて pin_uv_auth_protocols で採れる値です。<br>私の持っているセキュリティキーの場合は 1 でした。

##### pinUvAuthParam

[仕様](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#getCredsMetadata)では **authenticate(pinUvAuthToken, getCredsMetadata (0x01))** だっつうことなのですが意味不明ですね。<br>以下の方法で求めます。

- Protocol One なんで [いつもの方法](https://qiita.com/gebo/items/2c6e854fadebaaa45cc7)で pinUvAuthToken を求めます。32byteのバイナリデータです。
- 32byteの pinUvAuthToken を Key , 1byteの 0x01 を Message として HMAC-SHA256 を求めます、これは32byteのバイナリデータです。私のコード(Rust)ではhmacクレートを使っています、簡単です。
- 先程求めた32byteのHMAC-SHA256の先頭16Byte(0〜16番目)がpinUvAuthParamです。つまり、16byteのバイナリデータですね。



### enumerateRPsBegin,enumerateRPsGetNextRP

RP情報を取得します。enumerateRPsBeginで最初のRP情報と総RP数を取得し、enumerateRPsGetNextRPで次のRP情報を取得します。

- enumerateRPsBeginでとれる情報

  - rp (0x03) : RP名、PublicKeyCredentialRpEntity型、例 "webauthn.io"
  - rpIDHash (0x04) : RPIDハッシュ、32byteのバイナリデータ

  - totalRPs (0x05) : 登録されている総RP数、数値

- enumerateRPsGetNextRPでとれる情報

  - rp (0x03) : RP名
  - rpIDHash (0x04) : RPIDハッシュ

#### pinUvAuthProtocol,pinUvAuthParam

getCredsMetadataとほぼ同じです、pinUvAuthParamの求め方が少し違います。

- enumerateRPsBeginのとき → authenticate(pinUvAuthToken, **0x02**)
- enumerateRPsGetNextRPのとき → authenticate(pinUvAuthToken, **0x03**)



### enumerateCredentialsBegin,enumerateCredentialsGetNextCredential



