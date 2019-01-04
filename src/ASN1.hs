module ASN1 where

import Control.Arrow (left)
import Crypto.Number.Serialize (os2ip)
import Crypto.PubKey.ECC.Types (getCurveByName, Curve, CurveName(..), Point(..))
import Crypto.PubKey.ECC.ECDSA (PublicKey(..))
import Data.ByteString (ByteString)

import qualified Crypto.Types as CT
import qualified Data.ByteArray as BA
import qualified Data.ASN1.Types as AT
import qualified Data.ASN1.BinaryEncoding as ABE
import qualified Data.ASN1.Encoding as AE

parsePublicKeyDER :: [AT.ASN1] -> [AT.ASN1] -> Either String CT.PublicKey
parsePublicKeyDER [AT.OID arr] [AT.OctetString bs] = buildKey
    <$> ecParamsToCurveName arr
    <*> parsePoint bs
    where
        buildKey c q = CT.PublicKey { CT.curveName = c, CT.pk = PublicKey {public_curve = toCurve c, public_q = q} }
parsePublicKeyDER _ _ = Left "Unknown PubKey DER Format"

parsePointDER :: [AT.ASN1] -> Either String Point
parsePointDER [AT.OctetString bs] = parsePoint bs
parsePointDER _  = Left "Unknown DER Point Type"

parsePoint :: ByteString -> Either String Point
parsePoint ls
    -- | 0x04 means uncompressed, which is the only format we support atm
    -- | (https://tools.ietf.org/html/rfc5480#section-2.3.2)
    | BA.index ls 0 == 4 = Right $ go (BA.drop 1 ls)
    | otherwise = Left "Point was not uncompressed (no leading 0x04)"
    where
    go xs = Point (os2ip (BA.take len xs)) (os2ip (BA.drop len xs))
        where len = BA.length xs `div` 2

curveFromEcParams :: ByteString -> Either String CT.CurveName
curveFromEcParams bs = curveOf =<< left show (AE.decodeASN1' ABE.DER bs)
        where
            curveOf [AT.OID arr] = ecParamsToCurveName arr
            curveOf            _ = Left "Couldn't parse EC Params"

-- | These come from: https://tools.ietf.org/html/rfc5480#section-2.1.1.1
-- | Can generate these arrays in DER b64 format from: `openssl ecparam -name secp256k1`
-- |   - https://wiki.openssl.org/index.php/Command_Line_Elliptic_Curve_Operations
-- |
-- | And then decode this base64 encoded string using the following haskell:
-- |   - decodeASN1' DER $ decodeLenient $ pack "BgUrgQQACg=="`
-- |
-- |   - http://www.secg.org/SEC2-Ver-1.0.pdf (for secp256k1 (?))
-- |
ecParamsToCurveName :: Num a => Eq a => [a] -> Either String CT.CurveName
ecParamsToCurveName [1,2,840,10045,3,1,7] = Right CT.P256
ecParamsToCurveName        [1,3,132,0,10] = Right CT.SECP256K1
-- | https://tools.ietf.org/html/draft-ietf-curdle-pkix-10
ecParamsToCurveName        [1,3,101, 112] = Right CT.ED25519
ecParamsToCurveName                     _ = Left "No Known Curve Found"

curveToEcParams :: Num a => CT.CurveName -> [a]
curveToEcParams CT.P256      = [1,2,840,10045,3,1,7]
curveToEcParams CT.SECP256K1 = [1,3,132,0,10]
curveToEcParams CT.ED25519   = [1,3,101,110]

toCurve :: CT.CurveName -> Curve
toCurve CT.P256 = getCurveByName SEC_p256r1
toCurve CT.SECP256K1 = getCurveByName SEC_p256k1
-- | ED25519 is different, doesn't have a proper CurveName here
-- toCurve CT.ED25519 = getCurveByName
