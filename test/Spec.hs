
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
import qualified HSM
import qualified System.Crypto.Pkcs11 as PKCS


slotId :: CULong
slotId = 1165926823

kName :: String
kName = "test1"

library :: String
library = "/usr/local/lib/softhsm/libsofthsm2.so"

testKeys :: KeysConfig
testKeys = KeysConfig
  { keyName = kName
  , publicKeyHash = "unknown"
  , publicKey = "unknown"
  , hsmSlot = unsafeCoerce slotId
  }


main :: IO ()
main = do
  lib <- PKCS.loadLibrary library

  -- | Generate a new key in the HSM
  -- _ <- HSM.generatesecp421r1Key lib slotId "12345" kName

  -- | Generate pubkeyHash,pubKey from HSM
  pkh <- HSM.withPubKey lib "12345" (slotId, kName)
    (\obj -> do
      ecdsaParamsBS <- PKCS.getEcdsaParams obj
      pointBS <- PKCS.getEcPoint obj
      let e = ASN1.parsePublicKeyDER <$> decodeASN1' DER ecdsaParamsBS <*> decodeASN1' DER pointBS
          pk = join $ left show e
          in pure $ (\x -> (pubKeyHash x, pubKey x)) <$> pk)

  print pkh


  PKCS.releaseLibrary lib