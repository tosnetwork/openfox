# 📡 MQTT チャンネル

OpenFox は任意の MQTT クライアントをメッセージチャンネルとして使用できます。デバイスやサービスがブローカーにリクエストをパブリッシュし、OpenFox がサブスクライブして処理し、レスポンスをパブリッシュして返します。

## 🚀 クイックスタート

**1. `~/.openfox/config.json` にチャンネルを追加：**

```json
{
  "channel_list": {
    "mqtt": {
      "enabled": true,
      "type": "mqtt",
      "settings": {
        "broker": "tcp://localhost:1883",
        "agent_id": "assistant"
      }
    }
  }
}
```

**2. ゲートウェイを起動：**

```bash
openfox gateway
```

**3. 任意の MQTT クライアントからメッセージを送信：**

```bash
mosquitto_pub -t "/openfox/assistant/device1/request" \
  -m '{"text": "CPU使用率を確認してください"}'
```

**4. レスポンスを受信するためにサブスクライブ：**

```bash
mosquitto_sub -t "/openfox/assistant/device1/response"
```

---

## 📨 トピック構造

```
{prefix}/{agent_id}/{client_id}/request    # クライアント → OpenFox
{prefix}/{agent_id}/{client_id}/response   # OpenFox → クライアント
```

| セグメント | 説明 |
|-----------|------|
| `prefix` | トピックのプレフィックス。サーバー側で設定。デフォルト：`/openfox` |
| `agent_id` | OpenFox インスタンスの識別子。`agent_id` フィールドに設定 |
| `client_id` | クライアントが定義するセッション識別子。デバイスごとに同一の ID を使用するとコンテキストが維持される |

### メッセージペイロード（JSON）

```json
{ "text": "メッセージ内容" }
```

---

## ⚙️ 設定

### config.json

```json
{
  "channel_list": {
    "mqtt": {
      "enabled": true,
      "type": "mqtt",
      "settings": {
        "broker": "ssl://your-broker:8883",
        "agent_id": "assistant",
        "topic_prefix": "/openfox",
        "client_id": "",
        "keep_alive": 60,
        "qos": 0
      }
    }
  }
}
```

### .security.yml（認証情報）

ユーザー名とパスワードは `config.json` ではなく `~/.openfox/.security.yml` に保存します：

```yaml
channel_list:
  mqtt:
    settings:
      username: your_username
      password: your_password
```

### 設定フィールド

| フィールド | 場所 | 必須 | デフォルト | 説明 |
|-----------|------|------|-----------|------|
| `broker` | `settings` | はい | — | MQTT ブローカー URL。例：`tcp://host:1883`、`ssl://host:8883` |
| `agent_id` | `settings` | はい | — | エージェント識別子。トピックパスの一部として使用される |
| `topic_prefix` | `settings` | いいえ | `/openfox` | トピックの名前空間プレフィックス |
| `username` | `.security.yml` | いいえ | — | ブローカー認証のユーザー名 |
| `password` | `.security.yml` | いいえ | — | ブローカー認証のパスワード |
| `client_id` | `settings` | いいえ | 自動生成 | ブローカーに送信する paho クライアント ID。未設定の場合 `openfox-mqtt-{agent_id}-{8桁hex}` で自動生成。プロセスの生存期間中は固定され、再接続時も同じ ID を使用 |
| `keep_alive` | `settings` | いいえ | `60` | MQTT キープアライブ間隔（秒） |
| `qos` | `settings` | いいえ | `0` | パブリッシュおよびサブスクライブの QoS レベル：`0`、`1`、`2` |

### 環境変数

| 変数 | フィールド |
|------|----------|
| `OPENFOX_CHANNELS_MQTT_BROKER` | `broker` |
| `OPENFOX_CHANNELS_MQTT_AGENT_ID` | `agent_id` |
| `OPENFOX_CHANNELS_MQTT_TOPIC_PREFIX` | `topic_prefix` |
| `OPENFOX_CHANNELS_MQTT_USERNAME` | `username` |
| `OPENFOX_CHANNELS_MQTT_PASSWORD` | `password` |
| `OPENFOX_CHANNELS_MQTT_CLIENT_ID` | `client_id` |
| `OPENFOX_CHANNELS_MQTT_KEEP_ALIVE` | `keep_alive` |
| `OPENFOX_CHANNELS_MQTT_QOS` | `qos` |

---

## 🔄 再接続

接続が切断された場合、OpenFox は 5 秒間隔で自動的にブローカーに再接続します。再接続後はサブスクリプションも自動的に再確立されます。再接続時はブローカー側のクライアント ID が同一に保たれるため、ブローカーは同じセッションとして認識します。

---

## ⚠️ 注意事項

- **TLS**：SSL/TLS をサポートしています（ブローカー URL に `ssl://` を使用）。デフォルトでは証明書検証をスキップします。
- **ストリーミングレスポンス**：ストリーミング出力時はレスポンストピックに複数のメッセージが送信されます。順番に結合すると完全なレスポンスになります。
- **client_id とセッション ID の違い**：トピックパスの `client_id` はクライアントアプリケーションが設定するセッション識別子です。OpenFox がブローカーへの接続に使用する paho クライアント ID とは別の概念です。
- **複数インスタンス**：同じ `agent_id` で複数の OpenFox インスタンスを同一ブローカーに接続する場合、ブローカーレベルの競合を避けるために各インスタンスに異なる `client_id` を設定してください。
