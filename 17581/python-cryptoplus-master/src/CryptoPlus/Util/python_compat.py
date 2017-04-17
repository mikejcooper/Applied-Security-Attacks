from pkg_resources import parse_version
import CryptoPlus

if parse_version(CryptoPlus.__version__) > parse_version("2.0.1"):
        del CryptoPlus
        try:
               from CryptoPlus import *
        except:
               from CryptoPlus import *
