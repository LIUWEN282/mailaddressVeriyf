import re
import requests

# ✅ 1. メールアドレス形式の検証
def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# ✅ 2. メールアドレスからドメインを抽出
def extract_domain(email):
    return email.split('@')[-1].lower()

# ✅ 3. WhoisXML APIでドメインをチェック
def check_domain_whois(domain, api_key):
    url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
    payload = {
        "apiKey": api_key,
        "domainName": domain,
        "outputFormat": "JSON",
        "rdap": 0,
        "preferFresh": 1
    }

    response = requests.post(url, json=payload)
    if response.status_code == 200:
        data = response.json()
        record = data.get("WhoisRecord", {})
        registry_data = record.get("registryData", {})
        # まずWhoisRecordから取得
        registrant = record.get("registrant", {})
        organization = registrant.get("organization")
        country = registrant.get("country")
        # なければregistryData['registrant']から取得
        if not organization or not country:
            registry_registrant = registry_data.get("registrant", {})
            if not organization:
                organization = registry_registrant.get("organization")
            if not country:
                country = registry_registrant.get("country")
        # 登録日、更新日、有効期限
        created = registry_data.get("createdDate") or record.get("createdDate")
        updated = registry_data.get("updatedDate") or record.get("updatedDate")
        expires = registry_data.get("expiresDate") or record.get("expiresDate")
        # ステータス
        status = registry_data.get("status") or record.get("status")
        # ネームサーバー
        name_servers = []
        ns_data = registry_data.get("nameServers", {})
        if isinstance(ns_data, dict):
            name_servers = ns_data.get("hostNames", [])
        elif isinstance(ns_data, list):
            name_servers = ns_data
        # ドメイン年齢
        domain_age = record.get("estimatedDomainAge")
        # 生のWHOISテキスト
        raw_text = registry_data.get("rawText") or record.get("rawText")

        print(f"\n🌐 ドメイン: {domain}")
        print(f"🏢 登録組織: {organization or '不明'}")
        print(f"🌍 登録国: {country or '不明'}")
        print(f"📅 登録日: {created or '不明'}")
        print(f"🔄 最終更新日: {updated or '不明'}")
        print(f"⏳ 有効期限: {expires or '不明'}")
        print(f"🔗 ステータス: {status or '不明'}")
        print(f"🧑‍💻 ネームサーバー: {', '.join(name_servers) if name_servers else '不明'}")
        print(f"📈 ドメイン年齢: {domain_age or '不明'} 日")
        return organization is not None
    else:
        print(f"\n❌ WHOIS検索失敗: HTTP {response.status_code}")
        print(response.text)
        return False

# ✅ 4. メイン処理
def verify_email_domain(email, api_key):
    if not is_valid_email(email):
        print(f"❌ メールアドレス形式が正しくありません: {email}")
        return

    domain = extract_domain(email)
    print(f"✅ メールアドレス形式が正しい: {email}")
    print(f"🔎 ドメイン {domain} のWHOIS情報を検索中...")

    is_trusted = check_domain_whois(domain, api_key)
    if is_trusted:
        print("✅ ドメインに有効な登録者情報があります。信頼できます。")
    else:
        print("⚠️ 登録情報が不足している可能性があります。手動でご確認ください。")

# ✅ 5. サンプル実行
if __name__ == "__main__":
    API_KEY = "at_WpP6eKz3nGGwisW71pbUZOnVE41JM"
    email = "hideaki.suzuki@tohmatsu.co.jp"
    verify_email_domain(email, API_KEY)
