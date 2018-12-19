module HSM.IO.Internal where

import Control.Arrow (left)
import Control.Monad (join)
import Data.ASN1.Encoding (encodeASN1', decodeASN1')
import Data.ASN1.BinaryEncoding (DER(..))
import Data.ASN1.Types (ASN1(..))
import Data.ByteString.Char8 (pack, ByteString)
import Control.Exception (bracket, Exception, throw)
import Foreign.C.Types (CULong)
import Unsafe.Coerce (unsafeCoerce)

import HSM.Types
import HSM (HSM(..))
import Tezos.Keys (pubKey, pubKeyHash)

import qualified ASN1
import qualified Config as C
import qualified System.Crypto.Pkcs11 as PKCS


-- | TODO: Parse all slots + keys into an in-memory mapping of pubkey -> (slot,name), pubKeyHash -> (slot, name), name -> slot
-- | TODO: ^^ Or just verify the config on boot
withHsmIO :: LibraryPath -> UserPin -> (KeyHash -> Maybe C.KeysConfig) -> (HSM IO -> IO a) -> IO a
withHsmIO libPath pin find f = withLibrary libPath (f . _hsm)
    where
        _hsm :: PKCS.Library -> HSM IO
        _hsm l = HSM { sign = _sign l , getPublicKey = _getPublicKey l }

        _sign lib keyHash dat = withPrivKey lib pin (getSlotKh keyHash)
            (\privKey -> PKCS.sign (PKCS.simpleMech PKCS.Ecdsa) privKey dat Nothing)

        _getPublicKey lib keyHash = withPubKey lib pin (getSlotKh keyHash) (pure . show)

        -- | TODO: Clean this up, get rid of default bad values, etc.
        getSlotKh :: KeyHash -> (CULong, String)
        getSlotKh kh = maybe (0,"") (\x -> (unsafeCoerce (C.hsmSlot x), C.keyName x)) (find kh)


withLibrary :: LibraryPath -> (PKCS.Library -> IO a ) -> IO a
withLibrary l = bracket (PKCS.loadLibrary l) PKCS.releaseLibrary

withPubKey :: PKCS.Library -> UserPin -> (SlotId, String) -> (PKCS.Object -> IO a) -> IO a
withPubKey lib pin (slot, name) = withObj lib pin slot attrs
    where attrs = [PKCS.Class PKCS.PublicKey, PKCS.Label name]

withPrivKey :: PKCS.Library -> UserPin -> (SlotId, String) -> (PKCS.Object -> IO a) -> IO a
withPrivKey lib pin (slot, name) = withObj lib pin slot attrs
    where attrs = [PKCS.Class PKCS.PrivateKey, PKCS.Label name]

withObj :: PKCS.Library -> UserPin -> SlotId -> [PKCS.Attribute] -> (PKCS.Object -> IO a) -> IO a
withObj lib pin slot attrs f = withSession' False lib slot pin (find attrs)
    where
        find attrs s = PKCS.findObjects s attrs >>= go
        go (obj:xs) = f obj
        go [] = pure $ throw KeyNotFound

withSession' :: Bool -> PKCS.Library -> SlotId -> UserPin -> (PKCS.Session -> IO a) -> IO a
withSession' writeable lib slotId pin f =
    PKCS.withSession lib slotId writeable
        (\sess -> bracket
            (PKCS.login sess PKCS.User (pack pin))
            (const $ PKCS.logout sess)
            (pure $ f sess))

parseTZKey :: PKCS.Library -> UserPin -> (SlotId, String) -> IO (ByteString, ByteString)
parseTZKey l pin p = withPubKey l pin p
    (\obj -> do
      ecdsaParamsBS <- PKCS.getEcdsaParams obj
      pointBS <- PKCS.getEcPoint obj
      case join $ left show $
        ASN1.parsePublicKeyDER
            <$> decodeASN1' DER ecdsaParamsBS
            <*> decodeASN1' DER pointBS
        of
          Left e -> pure $ throw $ ParseError e
          Right x -> pure (pubKeyHash x, pubKey x))

generatesecp421r1Key :: PKCS.Library -> SlotId -> UserPin -> String -> IO (PKCS.Object, PKCS.Object)
generatesecp421r1Key l s p name = withSession' True l s p
        (PKCS.generateKeyPair
            (PKCS.simpleMech PKCS.EcdsaKeyPairGen)
            [PKCS.Token True, PKCS.EcdsaParams secp521r1EcdsaParams, PKCS.Label name]
            [PKCS.Token True, PKCS.Label name])

-- | https://www.ibm.com/developerworks/community/blogs/79c1eec4-00c4-48ef-ae2b-01bd8448dd6c/entry/Rexx_Sample_Generate_Different_Types_of_PKCS_11_Keys?lang=en
-- | Specified in 2.3.3 of:
-- | http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html
secp521r1EcdsaParams :: ByteString
secp521r1EcdsaParams = encodeASN1' DER seq
  where
    -- | From: https://tools.ietf.org/html/rfc5480
    curveName = [1,2,840,10045,3,1,7]
    seq = [OID curveName]