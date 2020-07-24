import os, json, datetime, random, hmac, base64, dbm
from bottle import Bottle, request, HTTPResponse, jinja2_template as template, TEMPLATE_PATH, abort
from urllib.parse import parse_qs, urlencode
import settings

BASEDIR = os.path.dirname(__file__)
TEMPLATE_PATH.append(BASEDIR)
AX_DATA = {
	'http://axschema.org/contact/email': '{email}',
	'http://axschema.org/namePerson': '{firstName} {lastName}',
	'http://axschema.org/namePerson/first': '{firstName}',
	'http://axschema.org/namePerson/last': '{lastName}'
}
SREG_DATA = {
	'email': '{email}',
	'fullname': '{firstName} {lastName}',
	'nickname': '{nickname}'
}

app = Bottle()

@app.get('/')
def index():
    request_id = str(10000 + random.randrange(90000))
    db = dbm.open(os.path.join(BASEDIR, 'req.db'), 'c')
    db[request_id] = request.query_string
    db.close()
    return template('login.html', request_id=request_id, username=request.query.get('openid.identity'))

@app.post('/')
def check_auth():
    if request.forms.get('openid.mode', None) != 'check_authentication':
        abort(400)
    signature = request.forms.get('openid.sig')
    assoc_handle = request.forms.get('openid.assoc_handle')
    signed_fields = request.forms.get('openid.signed')
    if assoc_handle != settings.HANDLE:
        return 'openid.mode:id_res\nis_valid:false\n'
    signed_data = []
    for field in signed_fields.split(','):
        if field == 'mode':
           signed_data.append('openid.mode:id_res')
           continue
        signed_data.append('openid.{}:{}'.format(field, request.forms.get('openid.' + field)))
    new_signature = base64.b64encode(
        hmac.new(
            settings.SECRET,
            '\n'.join(signed_data).encode('utf-8')
        ).digest()
    ).decode('utf-8')
    is_oid2 = request.forms.get('openid.ns', None) == 'http://specs.openid.net/auth/2.0'
    is_valid = 'true' if new_signature == signature else 'false'
    if is_oid2:
         return 'ns:http://specs.openid.net/auth/2.0\nopenid.mode:id_res\nis_valid:{}\n'.format(is_valid)
    return 'openid.mode:id_res\nis_valid:{}\n'.format(is_valid)

@app.post('/check')
def check_endpoint():
    response = HTTPResponse()
    request_id = request.forms.get('request_id')
    identity = request.forms.get('username')
    password = request.forms.get('password')
    with open(os.path.join(BASEDIR, 'userdb.json'), 'r') as f:
        userdb = json.load(f)
        if not identity in userdb or userdb[identity]['password'] != password:
            response.status = 302
            response.headers['Location'] = '/reject?request_id={}'.format(request_id)
            return response
        user_data = userdb[identity]
    db = dbm.open(os.path.join(BASEDIR, 'req.db'), 'c')
    oid_request = {k: v[0] for k, v in parse_qs(db[request_id].decode('utf-8')).items()}
    db.close()
    is_oid2 = 'openid.ns' in oid_request and oid_request['openid.ns'] == 'http://specs.openid.net/auth/2.0'
    oid_response = {
        'mode': 'id_res',
        'identity': identity,
        'return_to': oid_request['openid.return_to']
    }
    if is_oid2:
        oid_response['ns'] = 'http://specs.openid.net/auth/2.0'
        oid_response['op_endpoint'] = 'https://gears.headake.win/oid/'
        oid_response['response_nonce'] = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ') 
        oid_response['assoc_handle'] = settings.HANDLE
        oid_response['claimed_id'] = oid_request['openid.claimed_id']
    if 'openid.ax.required' in oid_request:
        ax_required = oid_request['openid.ax.required'].split(',')
        oid_response['ax.mode'] = 'fetch_response'
        for field in ax_required:
            oid_response['ax.type.' + field] = oid_request['openid.ax.type.' + field]
            oid_response['ax.value.' + field] = AX_DATA[oid_request['openid.ax.type.' + field]].format(**user_data)
    if 'openid.sreg.required' in oid_request:
        sreg_required = oid_request['openid.sreg.required'].split(',')
        for field in sreg_required:
            oid_response['sreg.' + field] = SREG_DATA[field].format(**user_data)
    oid_response_fields = oid_response.keys()
    signed_fields = ','.join(oid_response_fields)
    signature = base64.b64encode(
        hmac.new(
            settings.SECRET,
            '\n'.join(['openid.{}:{}'.format(k, oid_response[k]) for k in oid_response_fields]).encode('utf-8')
        ).digest()
    )
    oid_response['assoc_handle'] = settings.HANDLE
    oid_response['signed'] = signed_fields
    oid_response['sig'] = signature
    response.status = 302
    response.headers['Location'] = oid_request['openid.return_to'] + ('?' if oid_request['openid.return_to'].find('?') == -1 else '&') + urlencode({'openid.' + k: v for k, v in oid_response.items()})
    return response

@app.get('/reject')
def reject_request():
    request_id = request.query.get('request_id')
    db = dbm.open(os.path.join(BASEDIR, 'req.db'), 'c')
    oid_request = {k: v[0] for k, v in parse_qs(db[request_id].decode('utf-8')).items()}
    del db[request_id]
    db.close()
    response = HTTPResponse()
    response.status = 302
    response.headers['Location'] = oid_request['openid.return_to'] + ('?' if oid_request['openid.return_to'].find('?') == -1 else '&') + urlencode({'openid.mode': 'cancel'})
    return response

app.run(host='0.0.0.0', port=8891)
