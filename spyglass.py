from flask import Flask, flash, render_template, url_for, request
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import IPAddress
from ipwhois import IPWhois
import dns.resolver
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

def get_blacklists(ipaddress):
    bl_list = ['zen.spamhaus.org',
               'spam.abuse.ch',
               'cbl.abuseat.org',
               'virbl.dnsbl.bit.nl',
               'dnsbl.inps.de',
               'ix.dnsbl.manitu.net',
               'dnsbl.sorbs.net',
               'bl.spamcop.net',
               'xbl.spamhaus.org',
               'pbl.spamhaus.org',
               'dnsbl-1.uceprotect.net',
               'dnsbl-2.uceprotect.net',
               'dnsbl-3.uceprotect.net',
               'db.wpbl.info']
    bl_dict = {}
    for bl in bl_list:
        try:
            my_resolver = dns.resolver.Resolver()
            query = '.'.join(reversed(str(ipaddress).split('.'))) + '.' + bl
            answers = my_resolver.query(query, 'A')
            answer_txt = my_resolver.query(query, 'TXT')
            bl_dict[bl] = True

        except dns.resolver.NXDOMAIN:
            bl_dict[bl] = False
        except dns.resolver.NoAnswer:
            bl_dict[bl] = False
        except dns.resolver.NoNameservers as error:
            print(error)
    return bl_dict

@app.route('/')
def index():
    form = IPAddressForm()
    form.ipaddress.data = '8.8.8.8'
    #form.ipaddress.data = request.environ['REMOTE_ADDR']

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
        asn_description = asn_data['asn_description']
        network_handle = asn_data['network']['handle']
        network_name = asn_data['network']['name']
        asn_country_code = asn_data['asn_country_code']
        blacklists = get_blacklists(ipaddress)
        print(blacklists)
        #print(blacklists)
        
    else:
        flash('Not a valid IPv4 Address')

    return render_template('analyze.html',
            ipaddress=ipaddress,
            asn=asn,
            asn_cidr=asn_cidr,
            network_handle=network_handle,
            network_name=network_name,
            asn_description=asn_description,
            asn_country_code=asn_country_code,
            blacklists=blacklists,
            form=form)
