module HSM
    ( HSM (..)
    , withHsmIO
    ) where

import Control.Exception (bracket)
import qualified System.Crypto.Pkcs11 as PKCS
import Data.ByteString.Char8 (pack, unpack, ByteString)
import qualified Data.ByteString as BS
import Foreign.C.Types (CULong)
import Data.Word (Word64)
import Unsafe.Coerce (unsafeCoerce)
import Data.Hex as Hex
import Data.Maybe (isJust)

import qualified Config as C

type PubKey = PKCS.Object
type PrivKey = PKCS.Object
type SlotId  = Word64

type LibraryPath = String
type UserPin = String
type KeyHash = String
type KeyName = String
type Data = ByteString
type SignedMessage = ByteString

data HSM f = HSM
    { sign   :: KeyHash -> Data -> f (Maybe SignedMessage)
    , hasKey :: KeyHash -> f Bool
    }

withHsmIO :: LibraryPath -> UserPin -> (KeyHash -> Maybe C.KeysConfig) -> (HSM IO -> IO a) -> IO a
withHsmIO libPath pin find f = bracket
    (PKCS.loadLibrary libPath)
    PKCS.releaseLibrary
    (f . _hsm)
    where
        _hsm l = HSM
            { sign = _sign l
            , hasKey = _hasKey l
            }

        _sign lib keyHash dat =
            withPrivKey lib pin (find keyHash) (\privKey -> do
                signed <- PKCS.sign (PKCS.simpleMech PKCS.Ecdsa) privKey dat Nothing
                pure $ Hex.hex signed)

        _hasKey lib keyHash = isJust <$> withPrivKey lib pin (find keyHash) (const $ pure True)


withPrivKey :: PKCS.Library -> UserPin -> Maybe C.KeysConfig -> (PKCS.Object -> IO a) -> IO (Maybe a)
withPrivKey lib pin m f = maybe
    (pure Nothing)
    (\kc -> withSession' False lib (C.hsmSlot kc) pin
            (\sess -> do
                objs <- PKCS.findObjects sess [PKCS.Class PKCS.PrivateKey, PKCS.Label (C.keyName kc)]
                case objs of
                    privKey:xs -> fmap Just (f privKey)
                    [] ->  pure Nothing))
    m

withSession' :: Bool -> PKCS.Library -> SlotId -> UserPin -> (PKCS.Session -> IO a) -> IO a
withSession' writeable lib slotId pin f =
    PKCS.withSession lib (unsafeCoerce slotId :: CULong) writeable
        (\sess -> bracket
            (PKCS.login sess PKCS.User (pack pin))
            (const $ PKCS.logout sess)
            (pure $ f sess))



-- | Helper functions to be used for HSM initialization

-- | https://www.ibm.com/developerworks/community/blogs/79c1eec4-00c4-48ef-ae2b-01bd8448dd6c/entry/Rexx_Sample_Generate_Different_Types_of_PKCS_11_Keys?lang=en
secp521r1 :: ByteString
secp521r1 = BS.pack [0x06,0x05,0x2b,0x81,0x04,0x00,0x23]

generatesecp421r1Key :: PKCS.Library -> SlotId -> UserPin -> String -> IO ()
generatesecp421r1Key l s p name = withSession' True l s p (\sess -> do
        _ <- PKCS.generateKeyPair
            (PKCS.simpleMech PKCS.EcKeyPairGen)
            [PKCS.Token True, PKCS.EcParams secp521r1, PKCS.Label name]
            [PKCS.Token True, PKCS.Label name]
            sess
        pure ())
