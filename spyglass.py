from flask import Flask, flash, render_template, url_for, request, jsonify, redirect
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import IPAddress
from ipwhois import IPWhois
from concurrent.futures import ThreadPoolExecutor
import ipaddress
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
    print("getting asn")
    form = IPAddressForm()

    print("getting object")
    obj = IPWhois(ipaddress)

    results = obj.lookup_rdap()
    #pprint.pprint(results)

    return results


def get_blacklists(ipaddress):
    print("getting blacklist")
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
    with ThreadPoolExecutor(max_workers=13) as executor:
        results = []
        for bl in bl_list:
            results.append(executor.submit(blquery, ipaddress, bl))

        bl_dict = {}
        for r in results:
            bl_dict.update(r.result())
        #print(bl_dict)

    return bl_dict


def blquery(ipaddress, bl):
    try:
        print(f'pulling: {bl}')
        my_resolver = dns.resolver.Resolver()
        query = '.'.join(reversed(str(ipaddress).split('.'))) + '.' + bl
        answers = my_resolver.query(query, 'A')
        answer_txt = my_resolver.query(query, 'TXT')
        listed = "Listed"

    except dns.resolver.NXDOMAIN:
        listed = "Not listed"
    except dns.resolver.NoAnswer:
        listed = "Not listed"
    except dns.resolver.NoNameservers as error:
        print(error)

    return {bl: listed}


def get_geoip(ipaddress):
    print("getting geoip")
    url = 'http://www.geoplugin.net/json.gp?ip=' + ipaddress
    #response = requests.request('GET', url)
    response = requests.get(url)

    return response.json()


@app.route('/')
def index():
    form = IPAddressForm()
    # prefil the form with detected IP.
    form.ipaddress.data = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)

    return render_template('index.html', form=form)


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    form = IPAddressForm(request.form)
    try:
        ipa = form.ipaddress.data
    except Exception as e:
        flash(e)
        return redirect(url_for('index'))
    try:
        if ipaddress.ip_address(ipa).is_private:
            flash('IP address is private. Please input a public IP.')
            return redirect(url_for('index'))
    except Exception as e:
        flash(str(e))
        return redirect(url_for('index'))

    asn_data = retrieve_asn(ipa)

    asn = asn_data['asn']
    asn_cidr = asn_data['asn_cidr']
    asn_description = asn_data['asn_description']
    network_handle = asn_data['network']['handle']
    network_name = asn_data['network']['name']
    asn_country_code = asn_data['asn_country_code']
    blacklists = get_blacklists(ipa)
    geoip_dict = get_geoip(ipa)
    geo_continent = geoip_dict['geoplugin_continentName']
    geo_country = geoip_dict['geoplugin_countryName']
    geo_city = geoip_dict['geoplugin_city']
    geo_latitude = geoip_dict['geoplugin_latitude']
    geo_longitude = geoip_dict['geoplugin_longitude']
    #pprint.pprint(geoip_dict)
    #print(blacklists)

    return render_template('analyze.html',
                           ipaddress=ipa,
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
