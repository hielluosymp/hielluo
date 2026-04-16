import os
import json
import re
import requests
import firebase_admin
from firebase_admin import credentials, auth
from flask import Flask, render_template, request, jsonify, Response, stream_with_context
import cohere
import google.generativeai as genai

if os.environ.get("GEMINI_API_KEY"):
    genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))

_sa = os.environ.get("FIREBASE_SERVICE_ACCOUNT")
cred = credentials.Certificate(json.loads(_sa) if _sa else "serviceAccountKey.json")
firebase_admin.initialize_app(cred)

app = Flask(__name__)
cohere_client = cohere.ClientV2(api_key=os.environ.get("COHERE_API_KEY"))

# Country name → ISO2 code mapping (common countries)
COUNTRY_MAP = {
    "afghanistan": "AF", "albania": "AL", "algeria": "DZ", "angola": "AO",
    "argentina": "AR", "armenia": "AM", "australia": "AU", "austria": "AT",
    "azerbaijan": "AZ", "bangladesh": "BD", "belarus": "BY", "belgium": "BE",
    "benin": "BJ", "bolivia": "BO", "bosnia": "BA", "botswana": "BW",
    "brazil": "BR", "bulgaria": "BG", "burkina faso": "BF", "burundi": "BI",
    "cambodia": "KH", "cameroon": "CM", "canada": "CA", "chad": "TD",
    "chile": "CL", "china": "CN", "colombia": "CO", "congo": "CG",
    "costa rica": "CR", "croatia": "HR", "cuba": "CU", "czech republic": "CZ",
    "denmark": "DK", "dominican republic": "DO", "ecuador": "EC", "egypt": "EG",
    "el salvador": "SV", "ethiopia": "ET", "finland": "FI", "france": "FR",
    "ghana": "GH", "greece": "GR", "guatemala": "GT", "guinea": "GN",
    "haiti": "HT", "honduras": "HN", "hungary": "HU", "india": "IN",
    "indonesia": "ID", "iran": "IR", "iraq": "IQ", "ireland": "IE",
    "israel": "IL", "italy": "IT", "jamaica": "JM", "japan": "JP",
    "jordan": "JO", "kazakhstan": "KZ", "kenya": "KE", "kuwait": "KW",
    "laos": "LA", "latvia": "LV", "lebanon": "LB", "libya": "LY",
    "lithuania": "LT", "madagascar": "MG", "malawi": "MW", "malaysia": "MY",
    "mali": "ML", "mauritania": "MR", "mexico": "MX", "moldova": "MD",
    "mongolia": "MN", "morocco": "MA", "mozambique": "MZ", "myanmar": "MM",
    "namibia": "NA", "nepal": "NP", "netherlands": "NL", "new zealand": "NZ",
    "nicaragua": "NI", "niger": "NE", "nigeria": "NG", "north korea": "KP",
    "norway": "NO", "oman": "OM", "pakistan": "PK", "panama": "PA",
    "paraguay": "PY", "peru": "PE", "philippines": "PH", "poland": "PL",
    "portugal": "PT", "qatar": "QA", "romania": "RO", "russia": "RU",
    "rwanda": "RW", "saudi arabia": "SA", "senegal": "SN", "serbia": "RS",
    "sierra leone": "SL", "singapore": "SG", "somalia": "SO", "south africa": "ZA",
    "south korea": "KR", "south sudan": "SS", "spain": "ES", "sri lanka": "LK",
    "sudan": "SD", "sweden": "SE", "switzerland": "CH", "syria": "SY",
    "taiwan": "TW", "tajikistan": "TJ", "tanzania": "TZ", "thailand": "TH",
    "togo": "TG", "tunisia": "TN", "turkey": "TR", "turkmenistan": "TM",
    "uganda": "UG", "ukraine": "UA", "united arab emirates": "AE",
    "united kingdom": "GB", "uk": "GB", "united states": "US", "usa": "US",
    "us": "US", "uruguay": "UY", "uzbekistan": "UZ", "venezuela": "VE",
    "vietnam": "VN", "yemen": "YE", "zambia": "ZM", "zimbabwe": "ZW",
}

# Key World Bank indicators to fetch
INDICATORS = {
    "NY.GDP.MKTP.CD": "GDP (current US$)",
    "NY.GDP.PCAP.CD": "GDP per capita (current US$)",
    "SP.POP.TOTL": "Population",
    "FP.CPI.TOTL.ZG": "Inflation rate (%)",
    "SL.UEM.TOTL.ZS": "Unemployment rate (%)",
    "NE.EXP.GNFS.ZS": "Exports (% of GDP)",
    "NE.IMP.GNFS.ZS": "Imports (% of GDP)",
    "GC.DOD.TOTL.GD.ZS": "Central government debt (% of GDP)",
}


def extract_countries(text):
    text_lower = text.lower()
    found = []
    # Check multi-word names first
    for name in sorted(COUNTRY_MAP.keys(), key=len, reverse=True):
        if re.search(r'\b' + re.escape(name) + r'\b', text_lower):
            code = COUNTRY_MAP[name]
            if code not in [c for _, c in found]:
                found.append((name.title(), code))
    return found[:3]  # cap at 3 countries


def fetch_world_bank_data(country_code):
    results = {}
    for indicator, label in INDICATORS.items():
        try:
            url = (f"https://api.worldbank.org/v2/country/{country_code}"
                   f"/indicator/{indicator}?format=json&mrv=1&per_page=1")
            r = requests.get(url, timeout=4)
            data = r.json()
            if (isinstance(data, list) and len(data) > 1
                    and data[1] and data[1][0].get("value") is not None):
                val = data[1][0]["value"]
                year = data[1][0].get("date", "")
                results[label] = f"{val:,.2f} ({year})" if isinstance(val, float) else f"{val} ({year})"
        except Exception:
            pass
    return results


def build_world_bank_context(message):
    countries = extract_countries(message)
    if not countries:
        return ""
    sections = []
    for name, code in countries:
        data = fetch_world_bank_data(code)
        if data:
            lines = [f"**{name} (World Bank data)**"]
            for label, val in data.items():
                lines.append(f"- {label}: {val}")
            sections.append("\n".join(lines))
    if sections:
        return "Latest World Bank data:\n\n" + "\n\n".join(sections)
    return ""


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/argentaurius")
def argentaurius():
    return render_template("chatbots/argentaurius.html")


@app.route("/argentaurius/chat", methods=["POST"])
def argentaurius_chat():
    data = request.json
    if not data or not data.get("message", "").strip():
        return jsonify({"error": "Message is required"}), 400
    user_message = data["message"].strip()
    history = data.get("history", [])

    system_prompt = (
        "You are Argentaurius, an expert AI banker and financial analyst. "
        "You have deep knowledge of global economics, banking, finance, investment, "
        "monetary policy, and international development. "
        "You use World Bank data and authoritative sources to give precise, data-driven answers. "
        "When discussing countries or economies, reference the latest available statistics. "
        "Be professional, insightful, and thorough."
    )

    # Fetch World Bank data for any countries mentioned
    wb_context = build_world_bank_context(user_message)

    messages = [{"role": "system", "content": system_prompt}]
    for msg in history:
        role = "user" if msg["role"] == "user" else "assistant"
        messages.append({"role": role, "content": msg["content"]})

    # Inject World Bank data as additional context before the user message
    if wb_context:
        messages.append({"role": "user", "content": wb_context})
        messages.append({"role": "assistant", "content": "I have the latest World Bank data available. I'll incorporate it into my response."})

    messages.append({"role": "user", "content": user_message})

    def generate():
        try:
            stream = cohere_client.chat_stream(model="command-r-08-2024", messages=messages)
            for event in stream:
                try:
                    if (event.type == "content-delta" and event.delta and event.delta.message
                            and event.delta.message.content and event.delta.message.content.text):
                        yield f"data: {json.dumps({'chunk': event.delta.message.content.text})}\n\n"
                except AttributeError:
                    pass
            yield f"data: {json.dumps({'done': True})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return Response(stream_with_context(generate()), content_type='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route("/genesis/models")
def genesis_models():
    try:
        models = [m.name for m in genai.list_models() if "generateContent" in m.supported_generation_methods]
        return jsonify({"models": models})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/genesis")
def genesis():
    return render_template("chatbots/genesis.html")


@app.route("/genesis/chat", methods=["POST"])
def genesis_chat():
    data = request.json
    if not data or not data.get("message", "").strip():
        return jsonify({"error": "Message is required"}), 400
    user_message = data["message"].strip()
    history = data.get("history", [])

    model_alias = data.get("model", "genesis-1.0")
    model_map = {
        "genesis-1.0": "gemini-2.5-flash",
    }
    gemini_model = model_map.get(model_alias, "gemini-2.5-flash")

    gemini_history = []
    for msg in history:
        role = "user" if msg["role"] == "user" else "model"
        gemini_history.append({"role": role, "parts": [{"text": msg["content"]}]})

    def generate():
        try:
            model = genai.GenerativeModel(
                model_name=gemini_model,
                system_instruction=(
                    "You are Genesis, a helpful, thoughtful, and capable AI assistant. "
                    "You give clear, accurate, and well-structured responses. "
                    "Use markdown formatting where it helps clarity."
                )
            )
            chat = model.start_chat(history=gemini_history)
            response = chat.send_message(user_message, stream=True)
            for chunk in response:
                try:
                    if chunk.text:
                        yield f"data: {json.dumps({'chunk': chunk.text})}\n\n"
                except Exception:
                    pass
            yield f"data: {json.dumps({'done': True})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return Response(stream_with_context(generate()), content_type='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route("/auth/custom-token", methods=["POST"])
def custom_token():
    id_token = request.json.get("idToken")
    if not id_token:
        return jsonify({"error": "Missing idToken"}), 400
    try:
        decoded = auth.verify_id_token(id_token)
        custom = auth.create_custom_token(decoded["uid"])
        return jsonify({"customToken": custom.decode("utf-8")})
    except Exception as e:
        return jsonify({"error": str(e)}), 401


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
