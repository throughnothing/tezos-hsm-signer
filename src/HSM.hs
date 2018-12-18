module HSM where

import Control.Exception (bracket, Exception, throw)
import Data.ByteString.Char8 (pack, unpack, ByteString)
import Foreign.C.Types (CULong)
import Data.Word (Word64)
import Unsafe.Coerce (unsafeCoerce)

import qualified System.Crypto.Pkcs11 as PKCS
import qualified Config as C

type PubKey = PKCS.Object
type PrivKey = PKCS.Object
type SlotId  = PKCS.SlotId

type LibraryPath = String
type UserPin = String
type KeyHash = String
type KeyName = String
type Data = String
type SignedMessage = ByteString
type PublicKey = String

data HSM f = HSM
    { sign   :: KeyHash -> ByteString -> f ByteString
    , getPublicKey :: KeyHash -> f PublicKey
    }

data KeyNotFound = KeyNotFound deriving (Show)
instance Exception KeyNotFound

withHsmIO :: LibraryPath -> UserPin -> (KeyHash -> Maybe C.KeysConfig) -> (HSM IO -> IO a) -> IO a
withHsmIO libPath pin find f = bracket
    (PKCS.loadLibrary libPath)
    PKCS.releaseLibrary
    (f . _hsm)
    where
        _hsm :: PKCS.Library -> HSM IO
        _hsm l = HSM { sign = _sign l , getPublicKey = _getPublicKey l }

        _sign lib keyHash dat = withPrivKey lib pin (getSlotKh keyHash)
            (\privKey -> PKCS.sign (PKCS.simpleMech PKCS.Ecdsa) privKey dat Nothing)

        _getPublicKey lib keyHash = withPubKey lib pin (getSlotKh keyHash) (pure . show)

        -- | TODO: Clean this up, get rid of default bad values, etc.
        getSlotKh :: KeyHash -> (CULong, String)
        getSlotKh kh = maybe (0,"") (\x -> (unsafeCoerce (C.hsmSlot x), C.keyName x)) (find kh)


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