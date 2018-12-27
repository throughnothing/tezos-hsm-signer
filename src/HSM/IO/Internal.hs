module HSM.IO.Internal where

import Control.Arrow (left)
import Control.Exception (try, bracket, Exception, throw)
import Control.Monad (join)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT(..), MonadReader(..))
import Data.ASN1.Encoding (encodeASN1', decodeASN1')
import Data.ASN1.BinaryEncoding (DER(..))
import Data.ASN1.Types (ASN1(..))
import Data.ByteString(ByteString)
import Data.Map.Strict (Map, empty, insert, lookup)
import Data.Maybe (fromMaybe)
import Foreign.C.Types (CULong)
import Unsafe.Coerce (unsafeCoerce)

import Crypto.Types (CurveName(..), Signature(..), PublicKey(..))
import HSM.Types
import Tezos.Encoding (pubKeyStr, pubKeyHashStr)

import qualified ASN1
import qualified Config as C
import qualified Data.ByteString.Char8 as DBC
import qualified System.Crypto.Pkcs11 as PKCS

type LibraryPath = String
type UserPin = String
type SlotId  = Int

type HSMSession = ReaderT PKCS.Session IO

data HSMKey = HSMKey
  { name :: String
  , publicKeyHashStr :: String
  , publicKeyStr :: String
  , publicKey :: PublicKey
  , slot :: Int
  } deriving (Show)

withHsmIO :: LibraryPath -> UserPin -> [C.KeysConfig] -> (HSM IO -> IO a) -> IO a
withHsmIO libPath pin cks f = withLibrary libPath go
  where
    go lib = do
      keys <- findConfigKeys lib pin cks
      putStrLn $ "HSM Keys Found: " ++ show keys
      f $ mkHsm lib pin keys

mkHsm :: PKCS.Library -> UserPin -> Map String HSMKey -> HSM IO
mkHsm l pin keysMap = HSM { sign = _sign l , getPublicKey = _getPublicKey l }
  where
    _getPublicKey lib keyHash = orNotFound $ pure . publicKey <$> getKey keyHash

    _sign lib keyHash dat = orNotFound go
      where
        go = runSessionRO lib pin <$> slotM <*> (signHsm dat <$> keyM)
        slotM = getSlot keyHash
        keyM = getName keyHash


    getKey :: KeyHash -> Maybe HSMKey
    getKey kh = Data.Map.Strict.lookup kh keysMap

    getName :: KeyHash -> Maybe String
    getName kh = name <$> getKey kh

    getSlot :: KeyHash -> Maybe Int
    getSlot kh = slot <$> getKey kh


orNotFound :: Maybe (IO a) -> IO a
orNotFound Nothing = throw $ ObjectNotFound "Key Not Found."
orNotFound (Just x) = x

-- | Loop through each key in the config file, and check that it exists
-- | and can be properly parsed in the HSM.  Only return correctly parsed ones.
findConfigKeys :: PKCS.Library -> UserPin -> [C.KeysConfig] -> IO (Map String HSMKey)
findConfigKeys lib pin = foldr go (pure empty)
    where
      go key mp = do
        pkey <- runSessionRO lib pin slot $ getPubKey name
        insert (pubKeyHashStr pkey) (hsmKey pkey) <$> mp
          where
            name = C.keyName key
            slot = C.hsmSlot key
            hsmKey k = HSMKey
              { name = name
              , publicKeyHashStr = pubKeyHashStr k
              , publicKeyStr = pubKeyStr k
              , publicKey = k
              , slot = slot
              }


getPubKey :: String -> HSMSession PublicKey
getPubKey name = do
  key <- findPubKey name
  liftIO $ do
    ecdsaParamsBS <- PKCS.getEcdsaParams key
    pointBS <- PKCS.getEcPoint key
    case join $ left show $
      ASN1.parsePublicKeyDER
          <$> decodeASN1' DER ecdsaParamsBS
          <*> decodeASN1' DER pointBS
      of
        Left e -> pure $ throw $ ParseError e
        Right pk -> pure pk


withLibrary :: LibraryPath -> (PKCS.Library -> IO a ) -> IO a
withLibrary l = bracket (PKCS.loadLibrary l) PKCS.releaseLibrary

findPrivKey :: String -> HSMSession PKCS.Object
findPrivKey name = find1Obj [PKCS.Class PKCS.PrivateKey, PKCS.Label name, PKCS.Token True]

findPubKey :: String -> HSMSession PKCS.Object
findPubKey name = find1Obj [PKCS.Class PKCS.PublicKey, PKCS.Label name, PKCS.Token True]

signHsm :: ByteString -> String -> HSMSession Signature
signHsm dat keyName = do
  privKey <- findPrivKey keyName
  curve <- ecdsaCurve privKey
  sig <- liftIO $ PKCS.sign (PKCS.simpleMech PKCS.Ecdsa) privKey dat Nothing
  pure $ Signature curve sig


find1Obj :: [PKCS.Attribute] -> HSMSession PKCS.Object
find1Obj attrs = do
  sess <- ask
  liftIO $ PKCS.findObjects sess attrs >>= go
  where
    go (x:xs) = pure x
    go [] = pure $ throw $ ObjectNotFound (show attrs)

ecdsaCurve :: PKCS.Object -> HSMSession CurveName
ecdsaCurve obj = liftIO $ do
    ecdsaParamsBS <- PKCS.getEcdsaParams obj
    case ASN1.curveFromEcParams ecdsaParamsBS of
      Left e -> pure $ throw $ UnknownEcdsaParams e
      Right a -> pure a

runSessionRO :: PKCS.Library -> UserPin -> SlotId -> HSMSession a -> IO a
runSessionRO = runSession' False

runSessionRW :: PKCS.Library -> UserPin -> SlotId -> HSMSession a -> IO a
runSessionRW = runSession' True

runSession' :: Bool -> PKCS.Library -> UserPin -> SlotId -> HSMSession a -> IO a
runSession' writeable lib pin slotId hsms =
  PKCS.withSession lib (unsafeCoerce slotId) writeable
      (\sess -> bracket
          (PKCS.login sess PKCS.User (DBC.pack pin))
          (const $ PKCS.logout sess)
          (pure $ runReaderT hsms sess))

generateKeyPair :: CurveName -> String -> HSMSession (PKCS.Object, PKCS.Object)
generateKeyPair curve name = do
    sess <- ask
    liftIO $ PKCS.generateKeyPair
        (PKCS.simpleMech PKCS.EcdsaKeyPairGen)
        [PKCS.Token True, PKCS.EcdsaParams ecdsaParams, PKCS.Label name]
        [PKCS.Token True, PKCS.Label name]
        sess
    where ecdsaParams = encodeASN1' DER [OID (ASN1.curveToEcParams curve)]
