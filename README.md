# DMirakurun
DMirakurun は、[chinachu/mirakurun](https://github.com/Chinachu/Mirakurun) を基盤として、日本のデジタル放送をより柔軟に扱うための改善と機能拡張に取り組んでいるフォークです。衛星波によるBS4K/BS8Kへの対応をきっかけに、MPEG-TS、TSMF、TLVを共通のストリームとして扱える実装を進めています。

## 主な追加機能

### TSMFを含むストリームの自動処理

MPEG-TS多重化（TSMF）を解析し、チャンネル内に含まれる各ストリームを`networkId`と`streamId`で識別します。`tsmfRelTs`をあらかじめ設定しなくても、`channels.yml`に登録されたチャンネルを初回および定期的に解析してストリームとサービスの対応を取得し、サービスの視聴やEPG取得時に適切な相対TSを自動で選択します。

受信したストリームが通常のMPEG-TS、TSMFに多重化されたTLV、TSMFに多重化されたMPEG-TS、またはTLVのまま伝送されたストリームのいずれであるかを自動判別し、それぞれに適した解析・フィルター処理へ振り分けます。そのため、ストリーム形式ごとにチャンネル設定を分けたり、形式をあらかじめ指定したりする必要はありません。

この仕組みはMPEG-TSに多重化されたTLV形式のストリームの受信を主な目的として実装しましたが、TSMFで伝送される通常のBSサービスやCATVなどにも利用できるようにしています。従来通り、必要に応じて、チャンネルストリームAPIの`tsmfRelTs`で相対TSを明示することもできます。

8K放送などの複数搬送波伝送方式では、TSMFの`groupId`と各キャリアの情報を基に、複数のチューナーから受信したデータを結合してTLVストリームを再構成します。

### TLV・MPEG-H MMTのネイティブ対応

TLVをTSへ変換することなく、Mirakurun内部でTLVとMPEG-H MMTを直接解析します。TLV-NIT、MH-SDT、MPT、MH-EIT、CDTなどから、ストリーム、サービス、番組、映像・音声、ロゴの情報を取得できます。

この機能は、[otya128/MMirakurun](https://github.com/otya128/MMirakurun)のMMT/TLV対応を基に、ストリーム処理、EPG、複数サービス、TSMFとの連携などを拡張して取り込んだものです。MMT/TLV対応の先行実装と、その基盤となる[otya128/arib-mmt-tlv-ts](https://github.com/otya128/arib-mmt-tlv-ts)を公開されたotya128氏に深く感謝します。

ストリームAPIではTS出力に加えて`format=tlv`によるTLV出力を選択できます。`tlvDecoder`でTLVを処理した後にTLVのまま配信したり、`tlvToTsDecoder`に[nekohkr/dantto4k](https://github.com/nekohkr/dantto4k)や[Till0196/mmt2ts](https://github.com/Till0196/mmt2ts)などのTLVからTS形式へ変換できるCLIを指定して、TSへ変換したりできます。これらの変換ツール自体は本リポジトリには含まれません。

### ロゴ配信ストリームの自動判別

MPEG-TSで伝送されるロゴについて、ロゴ配信サービス（ESS）のSIDを固定値で判定せず、NITのサービスリスト記述子、PATのサービス構成、PMTのストリーム識別子を組み合わせて、ESSとロゴデータを伝送するESを自動判別します。

従来のSID 929を前提としたBS/100°CSのロゴ取得に加えて、異なるSIDでロゴが配信されるCATVなどのストリームにも対応できます。DSM-CCの`LOGO-05`、`CS_LOGO-05`、`CATV_LOGO-05`、`JCHITS_LOGO-05`を識別し、受信したロゴを対応するサービスへ関連付けます。地上デジタル放送のCDTによるロゴ取得も引き続き利用できます。

### 複数の受信経路を表す`route`

チャンネルに`route`、チューナーに`routes`を設定し、地上波（`TER`）、衛星（`SAT`）、CATV（`CATV`）、光再送信（`HIKARI`）などの受信経路を区別できます。同じ`networkId`と`streamId`を持つ放送を、衛星から直接受信する経路と、変調変換による再放送から受信する経路のどちらからでも同一のストリームとして扱えます。

`route`を省略した場合は、従来のチャンネルタイプに応じて`GR`は`TER`、`BS`、`CS`、`SKY`は`SAT`として扱われます（`BS4K`も`SAT`です）。そのため、複数経路を使用しない従来の`channels.yml`は、`route`を追加せずにそのまま利用できます。

同じ放送を受信経路ごとに別のチャンネルタイプとして扱う必要がなくなり、サーバー側では利用可能な経路とチューナーを一つの候補集合として管理できます。一方の経路が使用中または利用できない場合にも、同じストリームを受信できる別の経路を候補にできます。

サービス情報には、後方互換性のための`channel`に加えて、同じストリームを受信できる全経路を格納する`channels`を追加しています。`channel`は`channels`の先頭要素であるため、従来どおり`channel`を取り出してチャンネルAPIから選局するクライアントでは、先頭の経路だけが選択対象になります。

従来のMirakurunの機能と選局方法を利用する範囲では、既存のクライアントをそのまま使用できます。複数経路の自動選択やフォールバックを最大限活用するには、クライアント側で`networkId`と`streamId`によるストリーム指定を実装するか、サービスの`channels`から経路を指定できるようにしてください。

### ストリーム単位のAPIとデータモデル

- `/api/streamids`、`/api/streamids/{networkId}`、`/api/streamids/{networkId}/{streamId}`、`/api/streamids/{networkId}/{streamId}/stream`を追加しています。
- チャンネル、放送サービスを`networkId`と`streamId`に関連付け、TS、TSMF内のTS、TLVを共通の方法で検索・配信します。
- チャンネル、サービス、番組のストリームAPIで`format=ts|tlv`を選択できます。省略時はTSを出力します。TSストリームをTLVへ変換する機能ではないため、TSに対する`format=tlv`の要求には対応しません。
- `ChannelType`に`BS4K`、API型に`StreamId`、`StreamFormat`、`ChannelRoute`を追加しています。

## tuners.ymlの例

```yaml
# ISDB-T、ISDB-S、ISDB-S3、フレッツ・テレビ（ITU-T J.83 Annex B）用
- name: PT4K-0
  types:
    - GR
    - BS
    - CS
    - BS4K
  routes:
    - TER
    - SAT
    - HIKARI
  command: dvbv5-zap -a 0 -c /app/config/dvbconf-for-isdb/conf/dvbv5_channels_<route>.conf -r -P <channel>
  dvbDevicePath: /dev/dvb/adapter0/dvr0
  decoder: arib-b25-stream-test
  tlvDecoder: arib-b61-stream-test
  tlvToTsDecoder: dantto4k - -
  # tlvToTsDecoder: dantto4k - - --smartCardReaderName="Generic USB2.0-CRW [Smart Card Reader Interface] (20070818000000000) 00 00" --disableADTSConversion

# ISDB-T、ISDB-S、ISDB-S3、フレッツ・テレビ（ITU-T J.83 Annex B）用
- name: PT4K-1
  types:
    - GR
    - BS
    - CS
    - BS4K
  routes:
    - TER
    - SAT
    - HIKARI
  command: dvbv5-zap -a 1 -c /app/config/dvbconf-for-isdb/conf/dvbv5_channels_<route>.conf -r -P <channel>
  dvbDevicePath: /dev/dvb/adapter1/dvr0
  decoder: arib-b25-stream-test
  tlvDecoder: arib-b61-stream-test
  tlvToTsDecoder: dantto4k - -

# ISDB-T、ISDB-C用
- name: TBS6205SE-1
  types:
    - GR
    - BS
    - SKY
    - BS4K
  routes:
    - TER
    - CATV
  command: dvbv5-zap -a 2 -c /app/config/dvbconf-for-isdb/conf/dvbv5_channels_<route>.conf -r -P <channel>
  dvbDevicePath: /dev/dvb/adapter2/dvr0
  decoder: arib-b25-stream-test
  tlvDecoder: arib-b61-stream-test
  tlvToTsDecoder: dantto4k - -
```

`<route>`は、選択された経路に応じて小文字の`ter`、`sat`、`catv`、`hikari`のいずれかに置き換えられます。この例では、TBS6205SEを`TER`経路のISDB-Tと`CATV`経路のISDB-Cに使用します。PT4Kは、`TER`経路のISDB-T、`SAT`経路のISDB-SおよびISDB-S3、`HIKARI`経路のフレッツ・テレビ（ITU-T J.83 Annex B）に使用します。それぞれ対応する`dvbv5_channels_<route>.conf`を使って選局します。PT4Kによる`HIKARI`経路の受信も動作確認済みです。

`types`は受信したサービスをMirakurun上で分類するチャンネルタイプ、`routes`はチューナーが利用できる物理的な受信経路です。そのため、ISDB-Cやフレッツ・テレビで衛星放送の再放送を受信するチューナーには、`BS`、`SKY`、`BS4K`など、実際に扱うサービスのタイプも指定します。

PT4Kをこの構成で使用する場合は、[Till0196/tbs6812_drv](https://github.com/Till0196/tbs6812_drv)を利用できます。このドライバはPT4KをLinuxのDVBデバイスとして扱い、ISDB-T、ISDB-S（ISDB-S3を含む）、ISDB-C、DVB-S、ITU-T J.83 Annex Bの受信に対応しています。

## channels.ymlの例

同じ放送を衛星から直接受信する経路と、CATVの変調変換で受信する経路の両方を登録する例です。実際の`channel`は、使用するチューナーコマンドに合わせて変更してください。

```yaml
# 衛星から直接受信する経路
- name: <チャンネル名>
  type: BS
  route: SAT
  channel: BS13_1
  isDisabled: false

# 衛星系と同じ放送をCATVの変調変換で受信する経路
- name: <チャンネル名>
  type: BS
  route: CATV
  channel: 13
  # tsmfRelTs: 2
  isDisabled: false
```

登録した両方のチャンネルから同じ`networkId`と`streamId`を持つサービスが検出されると、一つのサービスの`channels`に両方の経路が格納されます。設定上で先に記述した経路が、後方互換用の`channel`として優先されます。チューナー側の`tuners.yml`にも、上の例のように受信可能な経路を`routes`で指定してください。

TSMF内のストリームを自動判別させる場合、通常は`tsmfRelTs`を`channels.yml`に記述する必要はありません。特定の相対TSへ固定したい場合にだけ明示してください。

## `recdvb`と`dvbv5-zap`の違い

### `recdvb`

[otya128/recdvb](https://github.com/otya128/recdvb)は、対応するキャラクターデバイスを直接使用し、`BS01_1`などのチャンネル名をコマンドへ渡して選局します。従来形式のチャンネルスキャンと組み合わせやすく、チューナーからのストリームは`recdvb`の標準出力をMirakurunが受け取ります。PT4Kで使用する場合は、本リポジトリの`/recdvb/pt1_dev.h`へ差し替えてください。

```yaml
command: recdvb --lnb 15 --dev 0 <channel> - -
```

### `dvbv5-zap`

`dvbv5-zap`はLinux DVB APIのアダプターを使用し、周波数、配送システム、Stream IDなどをDVBv5チャンネル設定ファイルから読み取って選局します。`<channel>`には設定ファイルのセクション名を指定する必要があります。このREADMEの設定例では、`<route>`で`ter`、`sat`、`catv`、`hikari`ごとの設定ファイルを切り替え、ストリームは`dvbDevicePath`からMirakurunが読み取ります。複数の配送システムや受信経路を同じチューナーで扱う場合に適しています。

同梱の`dvbv5_channels_sat.conf`では、`16625`や`45168`などのStream IDをセクション名に使用しています。そのため、`BS01_1`を生成する従来形式のスキャンをそのまま利用するには、`<channel>`と一致する`BS01_1`形式のセクションを持つDVBv5設定ファイルが必要です。Stream ID形式の設定を自動列挙するスキャンには、現時点では対応していません。

## スキャン

従来からの範囲指定によるチャンネルスキャンは利用できます。BSでは`useSubCh=true`を指定すると、`BS01_0`、`BS01_1`のような形式でチャンネルを生成して順に選局します。これらのチャンネル名を受け付ける`recdvb`などの選局コマンドで使用できます。

一方、受信経路を考慮し、NITなどからStream ID形式の選局候補を列挙して`channels.yml`へ追加するスキャン機能は、現時点では実装していません。複数の受信経路を利用する場合や、Stream IDをセクション名とする`dvbv5-zap`設定を使用する場合は、それぞれの`channel`と`route`を`channels.yml`へ手動で追加してください。登録後のストリームおよびサービスの検出では、各経路が自動的に関連付けられます。

ＮＨＫ　ＢＳＰ８Ｋも自動スキャンされないため、`channels.yml`に手動で追加する必要があります。

```yaml
- name: ＮＨＫ　ＢＳＰ８Ｋ
  type: BS4K
  channel: '0xB0E0'
  serviceId: 102
  isDisabled: false
```

---

[![Mirakurun](https://gist.githubusercontent.com/kanreisa/0ab27d7771e97edce5a24cc81b9b8ce6/raw/8e08d3d91390794b139ed593e3a834a8b41f651c/logo-mirakurun_2025-03-29.svg)](https://github.com/Chinachu/Mirakurun)

# Mirakurun

A Japanese digital TV tuner API server specifically designed for "Air" (code name of the app in development).

[![npm version][npm-img]][npm-url]
[![npm downloads][downloads-image]][downloads-url]
[![Linux Build][azure-pipelines-img]][azure-pipelines-url]
[![tip for next commit](https://tip4commit.com/projects/43158.svg)](https://tip4commit.com/github/Chinachu/Mirakurun)
[![Backers on Open Collective](https://opencollective.com/Mirakurun/backers/badge.svg)](#backers)
[![Sponsors on Open Collective](https://opencollective.com/Mirakurun/sponsors/badge.svg)](#sponsors)

[**CHANGELOG**](CHANGELOG.md) | [**Setup Guide**](doc/Platforms.md) | [**Configuration**](doc/Configuration.md)

[**English**](README.md) | [**日本語**](README.ja.md)

## Docker

[![dockeri.co](https://dockeri.co/image/chinachu/mirakurun)][docker-url]

Reference: List of available [tags](https://hub.docker.com/r/chinachu/mirakurun/tags) (Docker Hub)

## Features

- HTTP RESTful API (Swagger / Open API 2.0)
- Advanced tuner process management
- Multiple stream broadcasting from a single tuning
- Stream priority
- MPEG-2 TS parser, filter
- Real-time EPG parser
- Support for various tuner devices and hybrid environments (chardev, DVB / ISDB-T, ISDB-S, DVB-S2)
- Automatic channel scanning
- Web UI
- IPTV server (M3U8 playlist, XMLTV)

#### Figure: Variety of the MPEG-2 TS Stream API

![](https://gist.githubusercontent.com/kanreisa/0ab27d7771e97edce5a24cc81b9b8ce6/raw/7409e229648e00b55404f9e8342dccb58bbb4ac4/mirakurun-fig-api-variety2.svg)

#### Figure: Stream Flow

![](https://gist.githubusercontent.com/kanreisa/0ab27d7771e97edce5a24cc81b9b8ce6/raw/7409e229648e00b55404f9e8342dccb58bbb4ac4/mirakurun-fig-flow-stream2.svg)

## Setup Guide

👉 [**Setup Guide**](doc/Platforms.md)

## Configuration

👉 [**Configuration**](doc/Configuration.md)

## Web UI

```sh
# Admin UI
http://_your_mirakurun_ip_:40772/

# Swagger UI
http://_your_mirakurun_ip_:40772/api/debug
```

## Client Implementations

- [Rivarun](https://github.com/Chinachu/Rivarun)
- [BonDriver_Mirakurun](https://github.com/Chinachu/BonDriver_Mirakurun)
- Mirakurun Client ([Built-in](https://github.com/Chinachu/Mirakurun/blob/master/src/client.ts))
  - "Air" (in development codename)
  - [Chinachu γ](https://github.com/Chinachu/Chinachu/wiki/Gamma-Installation-V2)
  - [EPGStation](https://github.com/l3tnun/EPGStation)

## Contributing

- [CONTRIBUTING.md](CONTRIBUTING.md)

## Donations

- [Tip4Commit](https://tip4commit.com/github/Chinachu/Mirakurun) (BTC) - Distributed to all committers
- [Open Collective](https://opencollective.com/Mirakurun) (USD) - Pool (purpose undecided)

## Discord Community

- Invitation: https://discord.gg/X7KU5W9

## Contributors

This project exists thanks to all the people who contribute.
<a href="https://github.com/Chinachu/Mirakurun/graphs/contributors"><img src="https://opencollective.com/Mirakurun/contributors.svg?width=890&button=false" /></a>

## Backers

Thank you to all our backers! 🙏 [[Become a backer](https://opencollective.com/Mirakurun#backer)]

<a href="https://opencollective.com/Mirakurun#backers" target="_blank"><img src="https://opencollective.com/Mirakurun/backers.svg?width=890"></a>

## Sponsors

Support this project by becoming a sponsor. Your logo will show up here with a link to your website. [[Become a sponsor](https://opencollective.com/Mirakurun#sponsor)]

<a href="https://opencollective.com/Mirakurun/sponsor/0/website" target="_blank"><img src="https://opencollective.com/Mirakurun/sponsor/0/avatar.svg"></a>
<a href="https://opencollective.com/Mirakurun/sponsor/1/website" target="_blank"><img src="https://opencollective.com/Mirakurun/sponsor/1/avatar.svg"></a>
<a href="https://opencollective.com/Mirakurun/sponsor/2/website" target="_blank"><img src="https://opencollective.com/Mirakurun/sponsor/2/avatar.svg"></a>
<a href="https://opencollective.com/Mirakurun/sponsor/3/website" target="_blank"><img src="https://opencollective.com/Mirakurun/sponsor/3/avatar.svg"></a>
<a href="https://opencollective.com/Mirakurun/sponsor/4/website" target="_blank"><img src="https://opencollective.com/Mirakurun/sponsor/4/avatar.svg"></a>
<a href="https://opencollective.com/Mirakurun/sponsor/5/website" target="_blank"><img src="https://opencollective.com/Mirakurun/sponsor/5/avatar.svg"></a>
<a href="https://opencollective.com/Mirakurun/sponsor/6/website" target="_blank"><img src="https://opencollective.com/Mirakurun/sponsor/6/avatar.svg"></a>
<a href="https://opencollective.com/Mirakurun/sponsor/7/website" target="_blank"><img src="https://opencollective.com/Mirakurun/sponsor/7/avatar.svg"></a>
<a href="https://opencollective.com/Mirakurun/sponsor/8/website" target="_blank"><img src="https://opencollective.com/Mirakurun/sponsor/8/avatar.svg"></a>
<a href="https://opencollective.com/Mirakurun/sponsor/9/website" target="_blank"><img src="https://opencollective.com/Mirakurun/sponsor/9/avatar.svg"></a>

## Copyright / License

&copy; 2016- [kanreisa](https://github.com/kanreisa).

- Code: [Apache License, Version 2.0](LICENSE)
- Docs: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
- Logo: [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)

[npm-img]: https://img.shields.io/npm/v/mirakurun.svg
[npm-url]: https://npmjs.org/package/mirakurun
[downloads-image]: https://img.shields.io/npm/dm/mirakurun.svg?style=flat
[downloads-url]: https://npmjs.org/package/mirakurun
[azure-pipelines-img]: https://dev.azure.com/chinachu/Mirakurun/_apis/build/status/Chinachu.Mirakurun?branchName=master
[azure-pipelines-url]: https://dev.azure.com/chinachu/Mirakurun/_build/latest?definitionId=1&branchName=master
[docker-url]: https://hub.docker.com/r/chinachu/mirakurun
