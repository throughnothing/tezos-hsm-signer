module ASN1 where

import Crypto.Number.Serialize (i2osp, os2ip)
import Crypto.PubKey.ECC.Types (getCurveByName, Curve, CurveName(..), Point(..))
import Crypto.PubKey.ECC.ECDSA (PublicKey(..), PrivateKey(..))
import Data.ByteArray (ByteArrayAccess(..), unpack, take, drop, index)
import Data.ByteString (ByteString)

import qualified Data.ASN1.Types as AT

parsePublicKeyDER :: [AT.ASN1] -> [AT.ASN1] -> Either String PublicKey
parsePublicKeyDER [AT.OID arr] [AT.OctetString bs] = 
  (\c q -> PublicKey {public_curve = c, public_q = q})
    <$> oidToCurve arr
    <*> parsePoint bs
-- | TODO: Support other curves + formats
parsePublicKeyDER _ _ = Left "Unknown PubKey DER Format"

parsePointDER :: [AT.ASN1] -> Either String Point
parsePointDER [AT.OctetString bs] = parsePoint bs

parsePoint :: ByteString -> Either String Point
parsePoint ls
    -- | 0x04 means uncompressed, which is the only format we support atm
    -- | (https://tools.ietf.org/html/rfc5480#section-2.3.2)
    | index ls 0 == 4 = Right $ go (Data.ByteArray.drop 1 ls)
    | otherwise = Left "Point was not compressed"
    where
    go xs = let len = Data.ByteArray.length xs `div` 2
        in Point
            (os2ip (Data.ByteArray.take len xs))
            (os2ip (Data.ByteArray.drop len xs))

-- | TODO: Add more curve support.  Only parsing secp256r1 atm
oidToCurve :: [Integer] -> Either String Curve
oidToCurve [1,2,840,10045,3,1,7] = Right $ getCurveByName SEC_p256r1
oidToCurve _ = Left "No Curve Found"
  