# dify-selfhost-audit

[![ci](https://github.com/OTA-EITA/dify-selfhost-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/OTA-EITA/dify-selfhost-audit/actions/workflows/ci.yml)

Docker Compose でセルフホストした Dify の `docker/.env` と `docker-compose.yaml` を読み、公開済みのデフォルト鍵・パスワードや、危ない設定が残っていないかを調べる CLI です。
ファイルを読むだけで、Docker やネットワークには触りません。

A read-only CLI that checks a self-hosted Dify (Docker Compose) `.env` and `docker-compose.yaml` for published default secrets and risky settings. It never talks to Docker or the network.

対象バージョン: Dify 1.17.1 / dify-sandbox 0.2.15 / dify-plugin-daemon 0.6.10。各ルールの根拠は、このバージョンのソースの行にリンクしています。

## インストール

```sh
go install github.com/OTA-EITA/dify-selfhost-audit/cmd/dify-selfhost-audit@latest
```

## 使い方

```sh
cd dify/docker

# docker-compose.yaml と同じディレクトリの .env を読む
dify-selfhost-audit

# ファイルを明示する（--env は複数指定でき、後のファイルが優先）
dify-selfhost-audit --compose docker-compose.yaml --env .env --env envs/security.env

# プロファイルが無効なサービス（milvus、opengauss など）も含める
dify-selfhost-audit --all-profiles

# CI 向け: MEDIUM 以上で失敗、SARIF で出力
dify-selfhost-audit --fail-on medium --format sarif > dify.sarif
```

| オプション | 既定値 | 内容 |
|---|---|---|
| `--compose` | `./docker-compose.yaml` | 読む compose ファイル |
| `--env` | compose と同じ場所の `.env` | env ファイル。繰り返し指定可 |
| `--format` | `table` | `table` / `json` / `sarif` |
| `--fail-on` | `high` | この重大度以上があれば終了コード 1。`none` で常に 0 |
| `--all-profiles` | false | `COMPOSE_PROFILES` で無効なサービスもチェックする |
| `--list-rules` | | ルール一覧を表示 |

終了コード: `0` 閾値以上の指摘なし / `1` 閾値以上の指摘あり / `2` 引数やファイルのエラー。

### 読み方の前提

- 変数の展開は Compose と同じ規則（`${VAR:-default}`、`${VAR-default}`、入れ子、`$$`）で行い、値は `--env` で渡したファイルからだけ取ります。シェルの環境変数は読みません。
- 各コンテナの環境変数は `env_file`（記載順）→ `environment` の順に重ねて求めます。1.17.1 で分割された `envs/**/*.env` も、compose に書かれていれば自動で読みます。
- `.env.example` をそのまま調べるとき（`.env` がない）は、`--env` のファイルを `.env` の代わりとして扱い、その旨を表示します。
- compose を渡さない場合は、未設定の変数に 1.17.1 の compose のフォールバック値が入るものとして判定します。
- 鍵やパスワードの値は先頭 4 文字だけを表示します。

## チェック項目

| ID | 重大度 | 内容 | 根拠 (1.17.1) |
|---|---|---|---|
| DSA001 | HIGH | `SECRET_KEY` が 1.14.0 まで `.env.example` に載っていた値 | [.env.example@1.14.0 L104](https://github.com/langgenius/dify/blob/1.14.0/docker/.env.example#L104), [passport.py L9](https://github.com/langgenius/dify/blob/1.17.1/api/libs/passport.py#L9) |
| DSA002 | INFO | `SECRET_KEY` が空（自動生成してストレージに保存される） | [secret_key.py L12-38](https://github.com/langgenius/dify/blob/1.17.1/api/configs/secret_key.py#L12-L38) |
| DSA003 | LOW | `SECRET_KEY` が 32 文字未満、またはプレースホルダ | [secret_key.py L28](https://github.com/langgenius/dify/blob/1.17.1/api/configs/secret_key.py#L28) |
| DSA004 | MEDIUM | `INIT_PASSWORD` が空（最初に /install を開いた人が管理者になる） | [ext_application_services.py L693](https://github.com/langgenius/dify/blob/1.17.1/api/extensions/ext_application_services.py#L693), [init_validation_service.py L33-37](https://github.com/langgenius/dify/blob/1.17.1/api/services/init_validation_service.py#L33-L37) |
| DSA005 | MEDIUM | サンドボックスの API キーが `dify-sandbox` | [docker-compose.yaml L523](https://github.com/langgenius/dify/blob/1.17.1/docker/docker-compose.yaml#L523), [auth.go](https://github.com/langgenius/dify-sandbox/blob/0.2.15/internal/middleware/auth.go#L8-L15) |
| DSA006 | INFO | `CODE_EXECUTION_API_KEY` とサンドボックスのキーが不一致 | 同上 |
| DSA007 | MEDIUM | plugin daemon の `SERVER_KEY` が公開済みの既定値 | [docker-compose.yaml L597](https://github.com/langgenius/dify/blob/1.17.1/docker/docker-compose.yaml#L597) |
| DSA008 | MEDIUM | `PLUGIN_DIFY_INNER_API_KEY` が公開済みの既定値 | [docker-compose.yaml L239](https://github.com/langgenius/dify/blob/1.17.1/docker/docker-compose.yaml#L239) |
| DSA009 | MEDIUM | DB パスワードが `difyai123456` | [.env.example L77](https://github.com/langgenius/dify/blob/1.17.1/docker/.env.example#L77) |
| DSA010 | MEDIUM | Redis パスワード（`CELERY_BROKER_URL` 内を含む）が `difyai123456` | [.env.example L102, L121](https://github.com/langgenius/dify/blob/1.17.1/docker/.env.example#L102) |
| DSA011 | MEDIUM | Weaviate の API キーが公開済みの既定値 | [.env.example L166, L175](https://github.com/langgenius/dify/blob/1.17.1/docker/.env.example#L175) |
| DSA012 | MEDIUM | Weaviate の匿名リクエストが認可される（匿名アクセスが有効で、admin list が無効か `anonymous` を含む） | [.env.example L171-178](https://github.com/langgenius/dify/blob/1.17.1/docker/.env.example#L171-L178), [adminlist/authorizer.go L44-70](https://github.com/weaviate/weaviate/blob/v1.39.2/usecases/auth/authorization/adminlist/authorizer.go#L44-L70) |
| DSA013 | MEDIUM | オプションのデータストアが既定の資格情報のまま | [docker-compose.yaml](https://github.com/langgenius/dify/blob/1.17.1/docker/docker-compose.yaml#L856-L857) |
| DSA014 | MEDIUM | `DIFY_AGENT_SERVER_SECRET_KEY` が開発用の既定値 | [.env.example L278-281](https://github.com/langgenius/dify/blob/1.17.1/docker/.env.example#L278-L281) |
| DSA015 | MEDIUM | `DIFY_AGENT_API_TOKEN` が開発用の既定値 | [.env.example L257-260](https://github.com/langgenius/dify/blob/1.17.1/docker/.env.example#L257-L260) |
| DSA016 | HIGH | API の外向き HTTP が ssrf_proxy を通らない | [ssrf_proxy.py L86-101](https://github.com/langgenius/dify/blob/1.17.1/api/core/helper/ssrf_proxy.py#L86-L101) |
| DSA017 | LOW | ssrf_proxy でプライベート宛先を許可している | [docker-entrypoint.sh L32-56](https://github.com/langgenius/dify/blob/1.17.1/docker/ssrf_proxy/docker-entrypoint.sh#L32-L56), [squid.conf.template L12-13](https://github.com/langgenius/dify/blob/1.17.1/docker/ssrf_proxy/squid.conf.template#L12-L13) |
| DSA018 | MEDIUM | コンソール API の CORS が `*` | [feature/\_\_init\_\_.py L586-594](https://github.com/langgenius/dify/blob/1.17.1/api/configs/feature/__init__.py#L586-L594), [ext_blueprints.py L92-99](https://github.com/langgenius/dify/blob/1.17.1/api/extensions/ext_blueprints.py#L92-L99) |
| DSA019 | LOW | Web アプリ API の CORS が `*`（コードの既定値も `*`） | [feature/\_\_init\_\_.py L606-614](https://github.com/langgenius/dify/blob/1.17.1/api/configs/feature/__init__.py#L606-L614) |
| DSA020 | LOW | nginx が HTTP のみ | [nginx/docker-entrypoint.sh L5](https://github.com/langgenius/dify/blob/1.17.1/docker/nginx/docker-entrypoint.sh#L5) |
| DSA021 | LOW | `DEBUG=true` | [deploy/\_\_init\_\_.py L17-20](https://github.com/langgenius/dify/blob/1.17.1/api/configs/deploy/__init__.py#L17-L20) |
| DSA022 | LOW | `ENABLE_REQUEST_LOGGING=true`（リクエスト・レスポンス本文をログに出す） | [deploy/\_\_init\_\_.py L22-26](https://github.com/langgenius/dify/blob/1.17.1/api/configs/deploy/__init__.py#L22-L26) |
| DSA023 | LOW | `ALLOW_EMBED=true` | [web/proxy.ts L51-60](https://github.com/langgenius/dify/blob/1.17.1/web/proxy.ts#L51-L60) |
| DSA024 | MEDIUM | プラグイン署名の検証が無効 | [docker-compose.yaml L605](https://github.com/langgenius/dify/blob/1.17.1/docker/docker-compose.yaml#L605) |
| DSA025 | LOW | plugin daemon の pprof が有効 | [docker-compose.yaml L599](https://github.com/langgenius/dify/blob/1.17.1/docker/docker-compose.yaml#L599) |
| DSA101 | MEDIUM | ポートが全インターフェースに公開されている（nginx は INFO） | [docker-compose.yaml L642](https://github.com/langgenius/dify/blob/1.17.1/docker/docker-compose.yaml#L642) |
| DSA102 | HIGH | `privileged: true` | [docker-compose.yaml L1182](https://github.com/langgenius/dify/blob/1.17.1/docker/docker-compose.yaml#L1182) |
| DSA103 | HIGH | `docker.sock` をマウントしている | |
| DSA104 | MEDIUM | `network_mode: host` | |
| DSA105 | HIGH | サンドボックスが `internal: true` でないネットワークにいる | [docker-compose.yaml L536-537, L1302-1304](https://github.com/langgenius/dify/blob/1.17.1/docker/docker-compose.yaml#L1302-L1304) |

`SECRET_KEY` が空の場合、1.17.1 では API が鍵を生成してストレージの `.dify_secret_key` に保存するため、脆弱性としては扱いません（DSA002 は INFO）。ストレージのボリュームをバックアップすること、複数の api/worker で同じストレージを共有することが前提になります。
DSA003 の「32 文字」は目安です。Dify が自動生成する鍵は `secrets.token_urlsafe(48)`（64 文字）です。

## Dify 1.17.1 の既定ファイルに対する結果

```text
$ dify-selfhost-audit --compose docker-compose.yaml --env .env.example
SEVERITY  ID      SERVICE        LOCATION                 FINDING
MEDIUM    DSA004  api            .env.example:35          INIT_PASSWORD is empty: whoever opens /install first becomes admin
MEDIUM    DSA005  sandbox        .env.example:194         Code sandbox uses the published API key dify-sandbox
MEDIUM    DSA007  plugin_daemon  .env.example:225         Plugin daemon SERVER_KEY is the published default
MEDIUM    DSA008  api            .env.example:235         Inner API key for plugins is the published default
MEDIUM    DSA009  api            .env.example:77          Database password is the published default difyai123456
MEDIUM    DSA010  api            .env.example:102         Redis password is the published default difyai123456
MEDIUM    DSA010  api            .env.example:121         Redis password is the published default difyai123456
MEDIUM    DSA011  weaviate       .env.example:175         Weaviate API key is the published default
MEDIUM    DSA014  agent_backend  .env.example:281         DIFY_AGENT_SERVER_SECRET_KEY is the development default
MEDIUM    DSA015  agent_backend  .env.example:260         DIFY_AGENT_API_TOKEN is the development default
MEDIUM    DSA018  api            .env.example:131         Console API CORS allows any origin
MEDIUM    DSA101  plugin_daemon  docker-compose.yaml:642  Port published on all host interfaces
LOW       DSA019  api            .env.example:130         Web app API CORS allows any origin
LOW       DSA020  nginx          .env.example:285         nginx serves plain HTTP
INFO      DSA002  api            .env.example:34          SECRET_KEY is empty, so Dify generates and stores one
INFO      DSA101  nginx          docker-compose.yaml:813  Entry point published on all host interfaces
INFO      DSA101  nginx          docker-compose.yaml:814  Entry point published on all host interfaces

17 findings: 0 high, 12 medium, 2 low, 3 info
```

## 実環境での確認（dify-lab）

`.github/workflows/dify-lab.yml` は、GitHub Actions のランナー上で Dify 1.17.1 の既定構成を起動し、静的チェックの結果を実際のコンテナで確かめる手動実行専用のワークフローです（`workflow_dispatch` のみ）。公開ポートはすべて 127.0.0.1 に付け替えてから起動し、終わったら `docker compose down -v` で片付けます。

確認すること: 公開ポートの待ち受けアドレス、サンドボックスが既定キーを受け付け誤ったキーを拒否するか、ssrf_proxy が 169.254.169.254 や内部サービスへのリクエストを拒否するか、`INIT_PASSWORD` が空のときの `/console/api/setup`・`/console/api/init` の応答。結果はジョブのサマリーに出ます。

手元のマシンやサーバーでは実行しないでください。

1.17.1 での結果（2026-10-29）:

| 確かめたこと | 結果 |
|---|---|
| サンドボックス: キー `dify-sandbox` / 誤ったキー / キーなし | 200 / 401 / 401 |
| サンドボックス: plugin_daemon から既定キーで | 200 |
| Weaviate: 既定キーで1件書き込み → キーなしで読む / 書く | 200 → 403 / 403 |
| ssrf_proxy 経由: メタデータ、api、sandbox、plugin_daemon、weaviate、プロキシ自身 | すべて 403 |
| サンドボックス内のコード（`enable_network: true`）: api:5001 / plugin_daemon:5002 へ直接 | 200 / 404（応答あり） |
| サンドボックス内のコード: メタデータへプロキシ経由 | 403 |
| `INIT_PASSWORD` 空 / 設定ありで `/console/api/init` | `finished` / `not_started` |

`.env.example` は Weaviate の匿名アクセスを有効にしますが、admin list が有効なので、キーなしのリクエストは拒否されます。このため DSA012 は、admin list が無効か、リストに `anonymous` が入っているときだけ出します。

サンドボックスに渡される `HTTP_PROXY` は環境変数なので、コードがプロキシを使わなければ、同じ `ssrf_proxy_network` にいる api と plugin_daemon へ直接届きます。

## 開発

```sh
go test ./...
go vet ./...
```

## License

MIT
