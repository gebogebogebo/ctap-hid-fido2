# CTAP2 お勉強メモ#9 - CTAP 2.1 PRE authenticatorCredentialManagement



# はじめに

これはCTAPのお勉強をしたメモです。
**WebAuthn(ウェブオースン)ではなく、CTAP(シータップ)であります。**

今回はCTAP2.1(Review Draft)の **authenticatorCredentialManagement** です。



## CTAP 2.1 PRE ?

今の CTAP 2.0 に機能拡張を加えた仕様で Review Draft です。なので正式版は仕様が変わる可能性があります。<br>とはいえ 今世の中に出回っているセキュリティキーで既にこれを実装しているものがありまして  [authenticatorGetInfo](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#authenticatorGetInfo) で `FIDO_2_1_PRE` という version が採れるものがそれになります。<br>このセキュリティキーを使って **authenticatorCredentialManagement** を検証しました。



- 教科書
  - [CTAP仕様 Client to Authenticator Protocol (CTAP) Proposed Standard, Review Draft, March 09, 2021](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html)
- 教材
	- [YubiKey 5 Nano](https://www.yubico.com/jp/product/yubikey-5-nano/) - Firmware: 5.2.7
	- [SoloKey](https://solokeys.com/) - Firmware: 4.1.2
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



## サンプルコード

Rustで実装したクレートとサンプルコードがあります。コード見たほうが早いという人はこちら。

- **crate** : [ctap-hid-fido2(2.0.0)](https://crates.io/crates/ctap-hid-fido2)

- **sample** : [credential-management](https://github.com/gebogebogebo/ctap-hid-fido2/blob/master/examples/credential-management/src/main.rs)



## authenticatorCredentialManagement

[教科書 - 6.8 authenticatorCredentialManagement (0x0A)](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#authenticatorCredentialManagement)

authenticatorCredentialManagement は Residentkey で記録されたセキュリティキー内のクレデンシャルデータを管理するコマンドです。

> memo : 正式には authenticatorCredentialManagement を表すコマンドは `0x0A` ですが、FIDO_2_1_PRE では `0x41`です。そのへんの説明は [仕様書 6.13](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#prototypeAuthenticatorCredentialManagement) に書いてあります。

以下のようなサブコマンド形式になっています。

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

subCommand (0x01) に `getCredsMetadata(0x01)` を指定して、pinUvAuthProtocol(0x03)、pinUvAuthParam(0x04)を設定してCBORを投げると応答が返ってきます。

#### Parameters

authenticatorCredentialManagement の各サブコマンドにはpinUvAuthProtocol、pinUvAuthParamを指定する必要があります。これはPINの情報で、取得する情報がクレデンシャルなので当然といえば当然ですね。この生成シーケンスがめんどくさいです。

##### pinUvAuthProtocol

PIN/UV Auth プロトコルを指定します。簡単にいうとPINをどんなふうに暗号化しているかです。<br>仕様では  `1` ([6.5.6. PIN/UV Auth Protocol One](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#pinProto1)) と `2`  ([6.5.7. PIN/UV Auth Protocol Two](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#pinProto2)) がありまして。<br>どっちでもいいというわけではなくて、セキュリティキーに authenticatorGetInfo 投げて 採れる **pin_uv_auth_protocols** の値です。<br>私の持っているセキュリティキーの場合は `1`(Protocol One) でした。

##### pinUvAuthParam

[仕様](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#getCredsMetadata)では 

```
authenticate(pinUvAuthToken, getCredsMetadata (0x01))

authenticate(key, message) → signature
Computes a MAC of the given message.
```

だっつうことなのですが意味不明です。<br>以下の方法で求めます。

- Protocol One なんで [いつもの方法](https://qiita.com/gebo/items/2c6e854fadebaaa45cc7)で pinUvAuthToken を求めます。32byteのバイナリデータです。
- 32byteの `pinUvAuthToken` を **Key** , 1byteの `0x01` を **Message** として HMAC-SHA256 を求めます、32byteのバイナリデータが求まります。私のコード(Rust)では[hmacクレート](https://crates.io/crates/hmac)を使っています簡単です。
- 先程求めた32byteのHMAC-SHA256の先頭16Byte(0〜16番目)が **pinUvAuthParam** です。つまり、16byteのバイナリデータですね。

#### Response

- getCredsMetadataでとれる情報
  - existingResidentCredentialsCount (0x01) : セキュリキーに記録可能なクレデンシャルの最大数
  - maxPossibleRemainingResidentCredentialsCount (0x02) : 現在記録されているクレデンシャルの数

私の持ってるキーだと

- existingResidentCredentialsCount = 2

- maxPossibleRemainingResidentCredentialsCount = 50

でした。ResidetKeyしてクレデンシャルを登録していくと existingResidentCredentialsCount が増えていく感じです。



### enumerateRPsBegin/enumerateRPsGetNextRP

RP情報を取得します。enumerateRPsBeginで最初のRP情報と総RP数を取得し、enumerateRPsGetNextRPで次のRP情報を取得します。

#### Parameters

##### pinUvAuthProtocol/pinUvAuthParam

getCredsMetadataとほぼ同じです、pinUvAuthParamの求め方が少し違います。

- enumerateRPsBeginのとき → authenticate(pinUvAuthToken, **0x02**)
- enumerateRPsGetNextRPのとき → authenticate(pinUvAuthToken, **0x03**)

#### Response

- enumerateRPsBeginでとれる情報

  - rp (0x03) : RP名、PublicKeyCredentialRpEntity型、例 "webauthn.io"
  - rpIDHash (0x04) : RPIDハッシュ、32byteのバイナリデータ

  - totalRPs (0x05) : 登録されている総RP数、数値
- enumerateRPsGetNextRPでとれる情報

  - rp (0x03) : RP名
  - rpIDHash (0x04) : RPIDハッシュ



### enumerateCredentialsBegin/enumerateCredentialsGetNextCredential

パラメータで指定されたRPのクレデンシャルを取得します。enumerateCredentialsBeginで最初のクレデンシャルと総クレデンシャル数を取得し、enumerateCredentialsGetNextCredentialで次のクレデンシャルを取得します。

> Note : RP(Relying Party)があってその下にクレデンシャルというツリー構造ということがわかります。

#### Parameters
##### subCommandParams

サブパラメータで **rpIDHash** を指定します。enumerateRPsBegin/enumerateRPsGetNextRPで取れた値ですね。

##### pinUvAuthProtocol/pinUvAuthParam

pinUvAuthProtocolは他のコマンドと一緒です。<br>pinUvAuthParamがちょっとめんどくさいです。<br>

```
pinUvAuthParam = authenticate(pinUvAuthToken, enumerateCredentialsBegin(0x04) || subCommandParams)
```

この **0x04 || subCommandParams** が何なのかというと0x04(1byte)とsubCommandParamsを連結したたデータです。subCommandParamsがRPIDだらRPIDってことではなくCBOR Map型で指定する必要があります。具体的には [コード](https://github.com/gebogebogebo/ctap-hid-fido2/blob/7be9224ef70e83551177aed91b78660df85cb213/src/credential_management_command.rs#L79) を見たほうが良いかもしれません。<br>


#### Response

- enumerateCredentialsBeginでとれる情報

  - user (0x06) : ユーザーデータ、PublicKeyCredentialUserEntity型
  - credentialID (0x07) : クレデンシャルID、PublicKeyCredentialDescriptor型
  - publicKey (0x08) : 公開鍵、COSE_Key型
  - totalCredentials (0x09) : 総クレデンシャル数

- enumerateCredentialsGetNextCredentialでとれる情報

  - user (0x06) : ユーザーデータ、PublicKeyCredentialUserEntity型
  - credentialID (0x07) : クレデンシャルID、PublicKeyCredentialDescriptor型
  - publicKey (0x08) : 公開鍵、COSE_Key型



### deleteCredential

クレデンシャルを削除します。**これが欲しかった！**

#### Parameters

##### subCommandParams

[仕様書](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#deleteCredential)には

```
credentialId (0x02): PublicKeyCredentialDescriptor of the credential to be deleted.
```

って書いてあります、せっかちな私はここでしばらくハマりました。<br>credentialId**バイト配列ではなくPublicKeyCredentialDescriptor型で指定します。**CBOR Mapです。サンプルコードでは [fn create_public_key_credential_descriptor()](https://github.com/gebogebogebo/ctap-hid-fido2/blob/7be9224ef70e83551177aed91b78660df85cb213/src/credential_management_command.rs#L145) のあたりです。<br>(バイト配列のcredentialIdだけ渡せば特定できると思うけどめんどくさいですね)

##### pinUvAuthProtocol/pinUvAuthParam

```
pinUvAuthProtocol = 1
pinUvAuthParam = authenticate(pinUvAuthToken, deleteCredential (0x06) || subCommandParams)
```

ってことで。

#### Response

削除完了したらCTAP2_OK(0x00)が返ってきます。



### updateUserInformation
登録されているユーザー情報を変更します。

**このコマンドは動作確認できていません。確認できたら更新します。**



#### Parameters

##### subCommandParams

```
- subCommandParams (0x02): Map containing the parameters that need to be updated.
	- credentialId (0x02): PublicKeyCredentialDescriptor of the credential to be updated.
	- user (0x03): a PublicKeyCredentialUserEntity with the updated information.
```

[この通りにCBOR作って試しました](https://github.com/gebogebogebo/ctap-hid-fido2/blob/7be9224ef70e83551177aed91b78660df85cb213/src/credential_management_command.rs#L163)が なぜか  `0x11 CTAP2_ERR_CBOR_UNEXPECTED_TYPE`  エラーになってしまいます。なんでや(泣)。



##### pinUvAuthProtocol/pinUvAuthParam
``` 
pinUvAuthProtocol = 1
pinUvAuthParam = authenticate(pinUvAuthToken, updateUserInformation (0x07) || subCommandParams)
```
#### Response

更新したらCTAP2_OK(0x00)が返ってくるはずです。



# おつかれさまでした

[WebAuthn Level2](https://www.w3.org/TR/webauthn-2/) が W3C Recommendation になりました！ 

