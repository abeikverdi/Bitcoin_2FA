import json
import os
import random
import unittest

import bitcoin.ripemd as ripemd
from bitcoin import *

mprivkey = '1df56359e825cabaca7aad5f95913f3d511385a865f520716c3dfd2028355abf'

mpubkey = '04'+ electrum_mpk(mprivkey)

#print mpubkey

#addr = pubkey_to_address(mpubkey)

secret = raw_input('Enter the secret you receive from server: ')

#secret = '6e89f4170619c4fe3e79c9e7d51758e516ac58c73fbca2ee39cdd586c89c22ff'

newprivkey = add_privkeys(mprivkey,secret)
print newprivkey

newpubkey = '04' + electrum_mpk(newprivkey)
#print newpubkey

newaddr = pubkey_to_address(newpubkey)

#print newaddr