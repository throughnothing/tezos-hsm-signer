module Tezos.Encoding where

import Crypto.Number.Serialize (i2osp)
import Crypto.PubKey.ECC.Types (Point(..))
import Data.ASN1.Types ()
import Data.ByteString (ByteString)
import Data.ByteString.Char8 (unpack)
import Data.ByteArray (convert, cons)

import Crypto.Types (CurveName(..), PublicKey(..))
import Encoding (b58Check)
import Hash (blake2b160)
import Tezos.Constants (pkPrefix, pkhPrefix, skPrefix)

import qualified Crypto.PubKey.ECC.ECDSA as CE


pubKey :: PublicKey -> ByteString
pubKey p@(PublicKey c CE.PublicKey {CE.public_q = _}) =
        b58Check (pkPrefix c) $ pubKeyCompressed p

pubKeyHash :: PublicKey -> ByteString
pubKeyHash p@(PublicKey c CE.PublicKey {CE.public_q = _ }) =
        b58Check (pkhPrefix c) $ convert $ blake2b160 (pubKeyCompressed p)

pubKeyCompressed :: PublicKey -> ByteString
pubKeyCompressed (PublicKey _ CE.PublicKey {CE.public_q = Point x y})
        | y `mod` 2 == 1 = packWith 3
        | otherwise = packWith 2
        where packWith n = cons n $ i2osp x
-- | This should never happen, but we will fail in the event it does
pubKeyCompressed (PublicKey _ CE.PublicKey {CE.public_q = _ }) = error "Failed on a point @ infinity"

-- | TODO: Use our own PrivateKey type when we need this, so we can
-- | Serialize correctly based on the curve, instead of hard-coding
privKey :: CE.PrivateKey -> ByteString
privKey CE.PrivateKey {CE.private_d = d} = b58Check (skPrefix P256) $ i2osp d

pubKeyStr :: PublicKey -> String
pubKeyStr = unpack . pubKey

pubKeyHashStr :: PublicKey -> String
pubKeyHashStr = unpack . pubKeyHash
