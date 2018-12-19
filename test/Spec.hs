
import Control.Arrow (left)
import Control.Monad (join)
import Data.ByteString.Char8 (pack)
import Foreign.C.Types (CULong)
import Unsafe.Coerce (unsafeCoerce)

import Crypto.PubKey.ECC.ECDSA (PublicKey(..), PrivateKey(..))
import Data.ASN1.Encoding (decodeASN1')
import Data.ASN1.BinaryEncoding (DER(..))
import Data.ASN1.Types (ASN1(..), ASN1ConstructionType(..))

import Tezos.Keys (pubKeyHash, pubKey)
import Tezos.Operations (sign)
import Config (KeysConfig(..))

import qualified ASN1
import qualified HSM.IO.Internal as HSM
import qualified System.Crypto.Pkcs11 as PKCS


slotId :: CULong
slotId = 1165926823

kName :: String
kName = "test1"

library :: String
library = "/usr/local/lib/softhsm/libsofthsm2.so"

main :: IO ()
main = do
  pkh <- HSM.withLibrary library $ \l -> HSM.parseTZKey l "12345" (slotId,kName)
  print pkh
