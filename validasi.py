import warnings as _warnings
try:
    import _hashlib as _hashopenssl
except ImportError:
    _hashopenssl = None
    _openssl_md_meths = None
else:
    _openssl_md_meths = frozenset(_hashopenssl.openssl_md_meth_names)
import hashlib as _hashlib


trans_5C = bytes((x ^ 0x5C) for x in range(256))
trans_36 = bytes((x ^ 0x36) for x in range(256))

digest_size = None



class HMAC:

    blocksize = 64  # 512-bit HMAC;

    def __init__(self, key, msg=None, digestmod=''):

        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Masukan Byte Atau Byte Array, Tapi Ini %r" % type(key).__name__)

        if not digestmod:
            raise TypeError("Missing required parameter 'digestmod'.")

        if callable(digestmod):
            self.digest_cons = digestmod
        elif isinstance(digestmod, str):
            self.digest_cons = lambda d=b'': _hashlib.new(digestmod, d)
        else:
            self.digest_cons = lambda d=b'': digestmod.new(d)

        self.outer = self.digest_cons()
        self.inner = self.digest_cons()
        self.digest_size = self.inner.digest_size

        if hasattr(self.inner, 'block_size'):
            blocksize = self.inner.block_size
            if blocksize < 16:
                _warnings.warn('block_size of %d seems too small; using our '
                               'default of %d.' % (blocksize, self.blocksize),
                               RuntimeWarning, 2)
                blocksize = self.blocksize
        else:
            _warnings.warn('No block_size attribute on given digest object; '
                           'Assuming %d.' % (self.blocksize),
                           RuntimeWarning, 2)
            blocksize = self.blocksize


        self.block_size = blocksize

        if len(key) > blocksize:
            key = self.digest_cons(key).digest()

        key = key.ljust(blocksize, b'\0')
        self.outer.update(key.translate(trans_5C))
        self.inner.update(key.translate(trans_36))
        if msg is not None:
            self.update(msg)

    @property
    def name(self):
        return "hmac-" + self.inner.name

    def update(self, msg):
        self.inner.update(msg)

    def _current(self):
        h = self.outer.copy()
        h.update(self.inner.digest())
        return h

    def hexdigest(self):
        h = self._current()
        return h.hexdigest()

    def new(key, msg=None, digestmod=''):
 
        return HMAC(key, msg, digestmod)


def validasi(file, password, mac):
  password = bytes(password, 'UTF-8')
  file = bytes(file, 'UTF-8')
  mac = mac
  hmacc = HMAC.new(password, file, _hashlib.sha1)
  enkrip = hmacc.hexdigest()   
  return True if mac == enkrip else False
while True:
    fname = input('Masukan Nama file yang mau otentikasi: ')

    try:
        fread = open(fname)
        break
    except:
        print('Tidak dapat menemukan file yang dimaksud, tolong cek lagi.')
password = input('masukan Password Anda :')
mac = input('masukan MAC:')
hasil = validasi(fname,password,mac)
if hasil == True :
  print("File anda telah terotentikasi")
else:
  print("File anda tidak terontetikasi")