module HSM
    ( HSM (..)
    , hsmInterpreterIO
    , generatesecp421r1Key
    , SignedMessage
    ) where

import Control.Exception
import Control.Exception.Base
import qualified System.Crypto.Pkcs11 as PKCS
import Data.ByteString.Char8 (pack, unpack, ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import Data.Convertible.Base
import Foreign.C.Types (CULong)
import Data.Word
import Unsafe.Coerce


import qualified Data.Hex as HEX

type PubKey = PKCS.Object
type PrivKey = PKCS.Object
-- type SlotId  = PKCS.SlotId
type SlotId  = Word64

type LibraryPath = String
type UserPin = String
type KeyName = String
type Data = ByteString
type SignedMessage = ByteString

data HSMException = KeyNotFound deriving (Show)
instance Exception HSMException

-- | https://www.ibm.com/developerworks/community/blogs/79c1eec4-00c4-48ef-ae2b-01bd8448dd6c/entry/Rexx_Sample_Generate_Different_Types_of_PKCS_11_Keys?lang=en
secp521r1 :: ByteString
secp521r1 = BS.pack [0x06,0x05,0x2b,0x81,0x04,0x00,0x23]

newtype HSM f = HSM
    { sign :: SlotId -> KeyName -> Data -> f (Maybe SignedMessage)
    }

hsmInterpreterIO :: LibraryPath -> UserPin -> HSM IO
hsmInterpreterIO libPath pin = HSM
    { sign = \slotId keyName dat -> do
        withROSession libPath slotId pin (\sess -> do
            objs <- PKCS.findObjects sess [PKCS.Class PKCS.PrivateKey, PKCS.Label keyName]
            case objs of
                privKey:xs -> do
                    signed <- PKCS.sign (PKCS.simpleMech PKCS.Ecdsa) privKey dat Nothing
                    pure $ Just $ HEX.hex signed
                [] ->  pure $ Nothing)
    }


-- | Default is to use a read-only session
withROSession :: LibraryPath -> SlotId -> UserPin -> (PKCS.Session -> IO a) -> IO a
withROSession =  withSession' False

withSession' :: Bool -> LibraryPath -> SlotId -> UserPin -> (PKCS.Session -> IO a) -> IO a
withSession' writeable libPath slotId pin f = do
    lib <- PKCS.loadLibrary libPath
    r   <- PKCS.withSession lib (unsafeCoerce slotId :: CULong) writeable (\sess -> do
        PKCS.login sess PKCS.User (pack pin)
        x <- f sess
        PKCS.logout sess
        pure x)
    PKCS.releaseLibrary lib
    pure r


-- | Helper function to be used for initialization
generatesecp421r1Key :: LibraryPath -> SlotId -> UserPin -> String -> IO ()
generatesecp421r1Key l s p name = withSession' True l s p (\sess -> do
        _ <- PKCS.generateKeyPair
            (PKCS.simpleMech PKCS.EcKeyPairGen)
            [PKCS.Token True, PKCS.EcParams secp521r1, PKCS.Label name]
            [PKCS.Token True, PKCS.Label name]
            sess
        pure ())
