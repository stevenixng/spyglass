from flask import Flask, flash, render_template, url_for, request, jsonify, redirect
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import IPAddress
from ipwhois import IPWhois
import ipwhois
import dns.resolver
import pprint
import requests
import json


app = Flask(__name__, static_folder='static', static_url_path='')

app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'


class IPAddressForm(FlaskForm):
    ipaddress = StringField('ipaddress', validators=[IPAddress(message='Sorry, not a valid IP4 Address.')])


def retrieve_asn(ipaddress):
    form = IPAddressForm()
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
               'dnsbl-1.uceprotect.net',
               'dnsbl-2.uceprotect.net',
               'dnsbl-3.uceprotect.net',
               'psbl.surriel.com',
               'db.wpbl.info']
    bl_dict = {}
    for bl in bl_list:
        try:
            my_resolver = dns.resolver.Resolver()
            query = '.'.join(reversed(str(ipaddress).split('.'))) + '.' + bl
            answers = my_resolver.query(query, 'A')
            answer_txt = my_resolver.query(query, 'TXT')
            bl_dict[bl] = "Listed"

        except dns.resolver.NXDOMAIN:
            bl_dict[bl] = "Not listed"
        except dns.resolver.NoAnswer:
            bl_dict[bl] = "Not listed"
        except dns.resolver.NoNameservers as error:
            print(error)
    return bl_dict


def get_geoip(ipaddress):
    url = 'http://www.geoplugin.net/json.gp?ip=' + ipaddress
    response = requests.request('GET', url)

    return response.json()


@app.route('/')
def index():
    form = IPAddressForm()
    #form.ipaddress.data = '8.8.8.8'
    #form.ipaddress.data = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    form.ipaddress.data = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)

    return render_template('index.html', form=form)


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    form = IPAddressForm(request.form)
    ipaddress = form.ipaddress.data

    try:
        asn_data = retrieve_asn(ipaddress)
    except Exception as e:
        flash(e)
        return redirect(url_for('index'))

    asn = asn_data['asn']
    asn_cidr = asn_data['asn_cidr']
    asn_description = asn_data['asn_description']
    network_handle = asn_data['network']['handle']
    network_name = asn_data['network']['name']
    asn_country_code = asn_data['asn_country_code']
    blacklists = get_blacklists(ipaddress)
    geoip_dict = get_geoip(ipaddress)
    geo_continent = geoip_dict['geoplugin_continentName']
    geo_country = geoip_dict['geoplugin_countryName']
    geo_city = geoip_dict['geoplugin_city']
    geo_latitude = geoip_dict['geoplugin_latitude']
    geo_longitude = geoip_dict['geoplugin_longitude']
    #pprint.pprint(geoip_dict)
    #print(blacklists)

    return render_template('analyze.html',
                           ipaddress=ipaddress,
                           asn=asn,
                           asn_cidr=asn_cidr,
                           network_handle=network_handle,
                           network_name=network_name,
                           asn_description=asn_description,
                           asn_country_code=asn_country_code,
                           blacklists=blacklists,
                           geo_continent=geo_continent,
                           geo_country=geo_country,
                           geo_city=geo_city,
                           geo_latitude=geo_latitude,
                           geo_longitude=geo_longitude,
                           form=form)


@app.route('/api/')
def api_page():
    user_ipaddress = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    return render_template('api.html', user_ipaddress=user_ipaddress)


@app.route('/api/<ipaddress>')
def api(ipaddress):
    whois = ''
    form = IPAddressForm(request.form)
    try:
        whois = retrieve_asn(ipaddress)
    except Exception as e:
        flash(e)
        return redirect(url_for('api_page'))

    blacklists = get_blacklists(ipaddress)
    data = whois.copy()   # start with x's keys and values
    #data = whois.update(blacklists)    # modifies z with y's keys and values & returns None
    data = (whois, blacklists)
    return jsonify(data)


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404
