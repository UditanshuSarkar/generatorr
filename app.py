import os, json, hmac, string, urllib3, hashlib, codecs, logging, random, requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from flask import Flask, request, jsonify
from proto import registration_pb2, region_pb2, device_info_pb2, login_pb2
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', handlers=[logging.StreamHandler()])
logger = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
app = Flask(__name__)
logger.info("Loading proxy configuration")
with open("data/proxy.json", 'r') as file: originalproxies = json.load(file)
logger.info(f"Loaded {len(originalproxies)} proxies")
def get_random_user_agent(): return "GarenaMSDK/" + random.choice(("4.0.18P6","4.0.19P7","4.0.20P1","4.1.0P3","4.1.5P2","4.2.1P8","4.2.3P1","5.0.1B2","5.0.2P4","5.1.0P1","5.2.0B1","5.2.5P3","5.3.0B1","5.3.2P2","5.4.0P1","5.4.3B2","5.5.0P1","5.5.2P3")) + "(" + random.choice(("SM-A125F","SM-A225F","SM-A325M","SM-A515F","SM-A725F","SM-M215F","SM-M325FV","Redmi 9A","Redmi 9C","POCO M3","POCO M4 Pro","RMX2185","RMX3085","moto g(9) play","CPH2239","V2027","OnePlus Nord","ASUS_Z01QD")) + ";Android " + random.choice(("9","10","11","12","13","14")) + ";" + random.choice(("en-US","es-MX","pt-BR","id-ID","ru-RU","hi-IN")) + ";" + random.choice(("USA","MEX","BRA","IDN","RUS","IND")) + ";)"
def get_headers(): return {'User-Agent': get_random_user_agent(), 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/x-www-form-urlencoded", 'Expect': "100-continue", 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1", 'ReleaseVersion': "OB54"}
def get_random_proxy(): proxy = random.choice(originalproxies); return {"http": f"http://{proxy['username']}:{proxy['password']}@{proxy['host']}:{proxy['port']}", "https": f"http://{proxy['username']}:{proxy['password']}@{proxy['host']}:{proxy['port']}"}
def generate_random_username(): return ''.join(random.choice(string.ascii_letters) for _ in range(12))
def generate_secure_password(): return ''.join(random.choice(string.ascii_uppercase) for _ in range(64))
def aes_encrypt(data): return AES.new(b'Yg&tc%DEuh6%Zc^8', AES.MODE_CBC, b'6oyZDr22E3ychjM%').encrypt(pad(data, AES.block_size))
def encode_openid(openid): return ''.join(character if 32 <= ord(character) <= 126 else f'\\u{ord(character):04x}' for character in ''.join(chr(ord(character) ^ [48,48,48,50,48,49,55,48,48,48,48,48,50,48,49,55,48,48,48,48,48,50,48,49,55,48,48,48,48,48,50,48][index % 32]) for index, character in enumerate(openid)))
def create_guest_account(name=None,password=None,region=None,proxy=None):
    logger.info("Starting guest account creation")
    while True:
        username = name or generate_random_username(); password = password or generate_secure_password(); logger.info(f"Generated username: {username}")
        data = f"password={password}&client_type=2&source=2&app_id=100067"; signature = hmac.new(b'2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3',data.encode(),hashlib.sha256).hexdigest(); guest_headers = get_headers().copy(); guest_headers['Authorization'] = f"Signature {signature}"
        logger.info("Sending guest registration request"); response = requests.post("https://ffmconnect.live.gop.garenanow.com/oauth/guest/register",headers=guest_headers,data=data,proxies=proxy,verify=False)
        if response.status_code != 200: logger.error(f"Guest registration failed: {response.status_code}"); continue
        userid = response.json()['uid']; logger.info(f"Guest UID obtained: {userid}"); return get_access_token(userid,password,username,userid,region,proxy)
def get_access_token(userid, password, username, guestuserid, region, proxy):
    logger.info("Getting access token"); payload = {"uid": userid, "password": password, "response_type": "token", "client_type": "2", "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3", "client_id": "100067"}
    logger.info("Sending token grant request"); response = requests.post("https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant", headers=get_headers(), data=payload, proxies=proxy, verify=False)
    if response.status_code != 200: logger.error(f"Token grant failed: {response.status_code}"); return {"success": False, "error": f"Token grant failed: {response.status_code}"}
    data = response.json(); openid = data['open_id']; access_token = data["access_token"]; platform = data["platform"]; logger.info(f"OpenID: {openid}, Platform: {platform}"); encoded_field = codecs.decode(encode_openid(openid), 'unicode_escape').encode('latin1')
    return register_user(access_token, openid, platform, encoded_field, userid, password, username, guestuserid, region, proxy)
def register_user(access_token, openid, platform, encoded_field, userid, password, username, guestuserid, region, proxy):
    logger.info("Registering user in game"); request_object = registration_pb2.RegistrationRequest(); request_object.username = username; request_object.access_token = access_token; request_object.open_id = openid; request_object.app_id = 102000007; request_object.platform = platform; request_object.channel = 1; request_object.encoded_field = encoded_field
    logger.info("Sending registration request to game server"); response = requests.post("https://loginbp.ggblueshark.com/MajorRegister", headers=get_headers(), data=aes_encrypt(request_object.SerializeToString()), proxies=proxy, verify=False)
    if response.status_code != 200: logger.error(f"Registration failed: {response.status_code}"); return {"success": False, "error": f"Registration failed: {response.status_code}"}
    logger.info("Registration successful"); return login_user(userid, password, access_token, openid, platform, username, guestuserid, region, proxy)
def login_user(userid, password, access_token, openid, platform, username, guestuserid, region, proxy):
    logger.info("Logging in user"); device_info = device_info_pb2.DeviceInfo(); device_info.open_id = openid; device_info.access_token = access_token; device_info.orign_platform_type = int(platform); login_request = login_pb2.LoginReq(); login_request.open_id = openid; login_request.login_token = access_token; login_request.orign_platform_type = str(platform)
    logger.info("Sending login request"); response = requests.post("https://loginbp.ggblueshark.com/MajorLogin", headers=get_headers(), data=aes_encrypt(device_info.SerializeToString() + login_request.SerializeToString()), proxies=proxy, verify=False)
    login_response = login_pb2.LoginRes(); login_response.ParseFromString(response.content); token = login_response.token; logger.info(f"Login successful, token received")
    if region:
        logger.info(f"Setting region to: {region}"); region_request = region_pb2.RegionRequest(); region_request.region = region; cipher = AES.new(b'Yg&tc%DEuh6%Zc^8', AES.MODE_CBC, b'6oyZDr22E3ychjM%'); region_encrypted = cipher.encrypt(pad(bytes.fromhex(region_request.SerializeToString().hex()), AES.block_size)); region_headers = get_headers().copy(); region_headers['Authorization'] = f"Bearer {token}"
        logger.info(f"Region set response: {requests.post('https://loginbp.ggblueshark.com/ChooseRegion', data=region_encrypted, headers=region_headers, proxies=proxy, verify=False).status_code}")
        return generate_jwt_with_login_request_only(userid, password, access_token, openid, platform, username, guestuserid, region, proxy)
    return {"success": True, "account_token": token, "account_uid": login_response.account_id, "guest_password": password, "guest_uid": guestuserid, "nickname": username}
def generate_jwt_with_login_request_only(userid, password, access_token, openid, platform, username, guestuserid, region, proxy):
    logger.info("Generating final JWT token"); login_request = login_pb2.LoginReq(); login_request.open_id = openid; login_request.login_token = access_token; login_request.orign_platform_type = str(platform)
    response = requests.post("https://loginbp.ggblueshark.com/MajorLogin", headers=get_headers(), data=aes_encrypt(login_request.SerializeToString()), proxies=proxy, verify=False); login_response = login_pb2.LoginRes(); login_response.ParseFromString(response.content); final_token = login_response.token
    logger.info(f"Final token generated successfully. Account created - Username: {username}, UID: {login_response.account_id}, Region: {region}")
    return {"success": True, "account_token": final_token, "account_uid": login_response.account_id, "guest_password": password, "guest_uid": guestuserid, "nickname": username, "region": region}
@app.route('/create_account')
def create_account():
    logger.info("Received create account request"); name = request.args.get('name'); password = request.args.get('password'); region = request.args.get('region')
    if region:
        region = region.upper(); valid_regions = ["IND","BR","US","SAC","NA","SG","RU","ID","TW","VN","TH","ME","PK","BD","EUROPE"]
        if region not in valid_regions: logger.error(f"Invalid region requested: {region}"); return jsonify({"success": False, "error": f"Invalid region. Valid regions are: {', '.join(valid_regions)}"}), 400
    logger.info(f"Starting account creation with parameters: name={name}, region={region}"); proxy = get_random_proxy(); result = create_guest_account(name, password, region, proxy)
    if result.get('success'): logger.info(f"Account creation successful: {result}"); return jsonify(result)
    else: logger.error(f"Account creation failed: {result}"); return jsonify(result), 400
if __name__ == '__main__':
    logger.info("Starting Flask server on port 2009")
    app.run(host='0.0.0.0', port=30230, debug=False)