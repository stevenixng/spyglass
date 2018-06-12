from flask import Flask, flash, render_template, url_for, request
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import IPAddress
from ipwhois import IPWhois
import pprint


app = Flask(__name__)

app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

class IPAddressForm(FlaskForm):
    ipaddress = StringField('ipaddress', validators=[IPAddress(message='Sorry, not a valid IP4 Address.')])

def retrieve_asn(ipaddress):
    obj = IPWhois(ipaddress)
    results = obj.lookup_rdap()
    #pprint.pprint(results)
    return results

@app.route('/')
def index():
    form = IPAddressForm()
    #form.ipaddress.data = '8.8.8.8'
    form.ipaddress.data = request.environ['REMOTE_ADDR']

    return render_template('index.html', form=form)

@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    form = IPAddressForm(request.form)
    ipaddress = ''

    if form.is_submitted():
        print "submitted"

    if form.validate():
        print "valid"

    if form.validate_on_submit():
        #flash("IP is valid")
        ipaddress = form.ipaddress.data
        asn_data = retrieve_asn(ipaddress)
        asn = asn_data['asn']
        asn_cidr = asn_data['asn_cidr']
        #asn_name = asn_data['network']['name']
        asn_description = asn_data['asn_description']
        
    else:
        flash('Not a valid IPv4 Address')

    return render_template('analyze.html',
            ipaddress=ipaddress,
            asn=asn,
            asn_cidr=asn_cidr,
            asn_description=asn_description,
            form=form)
