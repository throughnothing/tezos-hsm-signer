module Tezos.Encoding where

import Crypto.Hash.Algorithms (Blake2b_160(..))
import Crypto.Number.Serialize (i2osp, os2ip)
import Crypto.PubKey.ECC.Types (Point(..))
import Crypto.Random.Types (MonadRandom)
import Data.ASN1.BinaryEncoding (DER(..))
import Data.ASN1.Encoding (encodeASN1')
import Data.ASN1.Types (ASN1(..), ASN1ConstructionType(..))
import Data.ByteString (ByteString)
import Data.ByteString.Char8 (unpack)
import Data.ByteArray (pack, convert, cons)

import Crypto.Types (CurveName(..), PublicKey(..))
import Encoding (b58Check)
import Hash (blake2b160, sha256)
import Tezos.Constants (pkPrefix, pkhPrefix, skPrefix)

import qualified Crypto.PubKey.ECC.ECDSA as CE


pubKey :: PublicKey -> ByteString
pubKey pk@(PublicKey c CE.PublicKey {CE.public_q = Point x y}) =
        b58Check (pkPrefix c) $ pubKeyCompressed pk

pubKeyHash :: PublicKey -> ByteString
pubKeyHash pk@(PublicKey c CE.PublicKey {CE.public_q = Point x y}) =
        b58Check (pkhPrefix c) $ convert $ blake2b160 (pubKeyCompressed pk)

pubKeyCompressed :: PublicKey -> ByteString
pubKeyCompressed (PublicKey c CE.PublicKey {CE.public_q = Point x y})
        | y `mod` 2 == 1 = packWith 3
        | otherwise = packWith 2
        where packWith n = cons n $ i2osp x

-- | TODO: Use our own PrivateKey type when we need this, so we can
-- | Serialize correctly based on the curve, instead of hard-coding
privKey :: CE.PrivateKey -> ByteString
privKey pk@CE.PrivateKey {CE.private_d = d} = b58Check (skPrefix P256) $ i2osp d

pubKeyStr :: PublicKey -> String
pubKeyStr = unpack . pubKey

pubKeyHashStr :: PublicKey -> String
pubKeyHashStr = unpack . pubKeyHash