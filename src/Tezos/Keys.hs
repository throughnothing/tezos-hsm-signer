module Tezos.Keys
        ( module Tezos.Keys
        , PublicKey
        , PrivateKey
        ) where

import Crypto.Hash.Algorithms (Blake2b_160(..))
import Crypto.Number.Serialize (i2osp, os2ip)
import Crypto.PubKey.ECC.Types (Point(..))
import Crypto.PubKey.ECC.ECDSA (PublicKey(..), PrivateKey(..), Signature(..), sign)
import Crypto.Random.Types (MonadRandom)
import Data.ASN1.BinaryEncoding (DER(..))
import Data.ASN1.Encoding (encodeASN1')
import Data.ASN1.Types (ASN1(..), ASN1ConstructionType(..))
import Data.ByteString (ByteString)
import Data.ByteArray (pack, convert, cons)

import Encoding (b58Check)
import Hash (blake2b160, sha256)
import Tezos.Constants (p256PKPrefix, p256PKHPrefix, p256SKPrefix, p256ESKPrefix)

pubKey :: PublicKey -> ByteString
pubKey pk@PublicKey {public_q = Point x y} = b58Check p256PKPrefix $ pubKeyCompressed pk

pubKeyHash :: PublicKey -> ByteString
pubKeyHash pk@PublicKey {public_q = Point x y} = b58Check p256PKHPrefix $ convert $ blake2b160 (pubKeyCompressed pk)

pubKeyCompressed :: PublicKey -> ByteString
pubKeyCompressed PublicKey {public_q = Point x y}
        | y `mod` 2 == 1 = packWith 3
        | otherwise = packWith 2
        where packWith n = cons n $ i2osp x

privKey :: PrivateKey -> ByteString
privKey pk@PrivateKey {private_d = d} = b58Check p256SKPrefix $ i2osp d