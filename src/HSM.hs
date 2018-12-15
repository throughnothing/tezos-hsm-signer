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
type SlotId  = Word64

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

data HSMError = KeyNotFound deriving (Show)
instance Exception HSMError

withHsmIO :: LibraryPath -> UserPin -> (KeyHash -> Maybe C.KeysConfig) -> (HSM IO -> IO a) -> IO a
withHsmIO libPath pin find f = bracket
    (PKCS.loadLibrary libPath)
    PKCS.releaseLibrary
    (f . _hsm)
    where
        _hsm l = HSM
            { sign = _sign l
            , getPublicKey = _getPublicKey l
            }

        _sign lib keyHash dat = withPrivKey lib pin (find keyHash)
            (\_ privKey -> PKCS.sign (PKCS.simpleMech PKCS.Ecdsa) privKey dat Nothing)

        _getPublicKey lib keyHash = withPrivKey lib pin (find keyHash) (\kc _ -> pure $ C.publicKey kc)

withPrivKey :: PKCS.Library -> UserPin -> Maybe C.KeysConfig -> (C.KeysConfig -> PKCS.Object -> IO a) -> IO a
withPrivKey lib pin m f = maybe
    (pure $ throw KeyNotFound)
    (\kc -> withSession' False lib (C.hsmSlot kc) pin
            (\sess -> do
                objs <- PKCS.findObjects sess [PKCS.Class PKCS.PrivateKey, PKCS.Label (C.keyName kc)]
                case objs of
                    privKey:xs -> f kc privKey
                    [] ->  pure $ throw KeyNotFound))
    m

withSession' :: Bool -> PKCS.Library -> SlotId -> UserPin -> (PKCS.Session -> IO a) -> IO a
withSession' writeable lib slotId pin f =
    PKCS.withSession lib (unsafeCoerce slotId :: CULong) writeable
        (\sess -> bracket
            (PKCS.login sess PKCS.User (pack pin))
            (const $ PKCS.logout sess)
            (pure $ f sess))