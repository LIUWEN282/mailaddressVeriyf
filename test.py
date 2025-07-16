import re
import requests

# ✅ 1. 检查邮箱格式是否合法
def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# ✅ 2. 提取邮箱中的域名
def extract_domain(email):
    return email.split('@')[-1].lower()

# ✅ 3. 调用 WhoisXML API 检查域名
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
        # 优先从 WhoisRecord 提取
        registrant = record.get("registrant", {})
        organization = registrant.get("organization")
        country = registrant.get("country")
        # 如果没有，再尝试从 registryData['registrant'] 提取
        if not organization or not country:
            registry_registrant = registry_data.get("registrant", {})
            if not organization:
                organization = registry_registrant.get("organization")
            if not country:
                country = registry_registrant.get("country")
        # 注册时间、更新时间、到期时间
        created = registry_data.get("createdDate") or record.get("createdDate")
        updated = registry_data.get("updatedDate") or record.get("updatedDate")
        expires = registry_data.get("expiresDate") or record.get("expiresDate")
        # 状态
        status = registry_data.get("status") or record.get("status")
        # 域名服务器
        name_servers = []
        ns_data = registry_data.get("nameServers", {})
        if isinstance(ns_data, dict):
            name_servers = ns_data.get("hostNames", [])
        elif isinstance(ns_data, list):
            name_servers = ns_data
        # 域名年龄
        domain_age = record.get("estimatedDomainAge")
        # 原始 WHOIS 文本
        raw_text = registry_data.get("rawText") or record.get("rawText")

        print(f"\n🌐 域名: {domain}")
        print(f"🏢 注册组织: {organization or '未知'}")
        print(f"🌍 注册国家: {country or '未知'}")
        print(f"📅 注册时间: {created or '未知'}")
        print(f"🔄 最近更新时间: {updated or '未知'}")
        print(f"⏳ 到期时间: {expires or '未知'}")
        print(f"🔗 状态: {status or '未知'}")
        print(f"🧑‍💻 域名服务器: {', '.join(name_servers) if name_servers else '未知'}")
        print(f"📈 域名年龄: {domain_age or '未知'} 天")
        return organization is not None
    else:
        print(f"\n❌ WHOIS 查询失败: HTTP {response.status_code}")
        print(response.text)
        return False

# ✅ 4. 主程序入口
def verify_email_domain(email, api_key):
    if not is_valid_email(email):
        print(f"❌ 邮箱格式非法: {email}")
        return

    domain = extract_domain(email)
    print(f"✅ 邮箱格式合法: {email}")
    print(f"🔎 正在查询域名: {domain} 的 WHOIS 信息...")

    is_trusted = check_domain_whois(domain, api_key)
    if is_trusted:
        print("✅ 域名有有效注册人信息，可视为可信。")
    else:
        print("⚠️ 可能缺乏注册信息，请人工核实。")

# ✅ 5. 示例调用
if __name__ == "__main__":
    API_KEY = "at_WpP6eKz3nGGwisW71pbUZOnVE41JM"
    email = "hideaki.suzuki@tohmatsu.co.jp"
    verify_email_domain(email, API_KEY)
