hs-otr
======

Create a signing key
--------------------

To create the DSA key you can do the following:
### Create the parameter file.
This file can be reused for as many keys as you want.

> openssl dsaparam -out \<parameterfile.pem\> 1024

The prime has to be 1024 bits in size, bigger key sizes unfortunately don't work with OTR.

### Create the keypair

> openssl gendsa -param \<parameterfile.pem\> -out \<keyfile.pem\>


Read the key
------------

Here's a chunk of code to get the key pair from the file. It requires the packages
*  pem
*  crypto-pubkey-types
*  asn1-types
*  asn1-encoding

```haskell
import           Crypto.Types.PubKey.DSA
import           Data.ASN1.BinaryEncoding
import           Data.ASN1.Encoding
import           Data.ASN1.Types
import qualified Data.ByteString.Lazy as BSL
import           Data.PEM

getKey = String ->  IO KeyPair
getKey keyFile = do
    Right ((PEM pName _ bs) : _) <- pemParseLBS `fmap` (BSL.readFile keyFile)
    let Right keysASN1 = decodeASN1 DER (BSL.fromChunks [bs])
    let Right (keyPair, _) = fromASN1 keysASN1
    return keyPair

```

Error handling is left as an exercise. ;-)