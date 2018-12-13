module HSM where
    -- ( HSM (..)
    -- , withHsmIO
    -- ) where

import Control.Exception (bracket, Exception, throw)
import Data.ByteString.Char8 (pack, unpack, ByteString)
import qualified Data.ByteString as BS
import Foreign.C.Types (CULong)
import Data.Word (Word64)
import Unsafe.Coerce (unsafeCoerce)
import Data.Hex as Hex
import Data.Maybe (isJust)
import qualified System.Crypto.Pkcs11 as PKCS

import qualified Encodings as E
import qualified Config as C

type PubKey = PKCS.Object
type PrivKey = PKCS.Object
type SlotId  = Word64

type LibraryPath = String
type UserPin = String
type KeyHash = String
type KeyName = String
type Data = E.HexString
type SignedMessage = ByteString
type PublicKey = String

data HSM f = HSM
    { sign   :: KeyHash -> Data -> f E.Base58String
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

        _sign lib keyHash dat =
            let dataToSign =  E.blake2b $ E.strToHex dat in
                withPrivKey lib pin (find keyHash) (\_ privKey -> do
                    signed <- PKCS.sign (PKCS.simpleMech PKCS.Ecdsa) privKey dataToSign Nothing
                    pure $ E.toBase58Str signed)

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



-- | Helper functions to be used for HSM initialization

-- | https://www.ibm.com/developerworks/community/blogs/79c1eec4-00c4-48ef-ae2b-01bd8448dd6c/entry/Rexx_Sample_Generate_Different_Types_of_PKCS_11_Keys?lang=en
secp521r1EcParams :: ByteString
secp521r1EcParams = BS.pack [0x06,0x05,0x2b,0x81,0x04,0x00,0x23]

generatesecp421r1Key :: PKCS.Library -> SlotId -> UserPin -> String -> IO ()
generatesecp421r1Key l s p name = withSession' True l s p (\sess -> do
        _ <- PKCS.generateKeyPair
            (PKCS.simpleMech PKCS.EcKeyPairGen)
            [PKCS.Token True, PKCS.EcParams secp521r1EcParams, PKCS.Label name]
            [PKCS.Token True, PKCS.Label name]
            sess
        pure ())
