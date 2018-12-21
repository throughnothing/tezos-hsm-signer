module HSM.IO.Internal where

import Control.Arrow (left)
import Control.Monad (join)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT(..), MonadReader(..))
import Data.ASN1.Encoding (encodeASN1', decodeASN1')
import Data.ASN1.BinaryEncoding (DER(..))
import Data.ASN1.Types (ASN1(..))
import Data.ByteString(ByteString)
import Control.Exception (bracket, Exception, throw)
import Foreign.C.Types (CULong)
import Unsafe.Coerce (unsafeCoerce)

import Crypto.Types (CurveName(..))
import HSM.Types
import Tezos.Keys (pubKey, pubKeyHash)
import Tezos.Types (Signature(..))

import qualified ASN1
import qualified Config as C
import qualified Data.ByteString.Char8 as DBC
import qualified System.Crypto.Pkcs11 as PKCS

type HSMSession = ReaderT PKCS.Session IO

-- | TODO: Verify the config against HSM on boot
withHsmIO :: LibraryPath -> UserPin -> (KeyHash -> Maybe C.KeysConfig) -> (HSM IO -> IO a) -> IO a
withHsmIO libPath pin find f = withLibrary libPath (f . _hsm)
  where
    _hsm :: PKCS.Library -> HSM IO
    _hsm l = HSM { sign = _sign l , getPublicKey = _getPublicKey l }

    _sign lib keyHash dat = runSessionRO lib (getSlot keyHash) pin $
      signHsm (getName keyHash) dat

    _getPublicKey lib keyHash = runSessionRO lib (getSlot keyHash) pin $
       show <$> findPubKey (getName keyHash)

    getName :: KeyHash -> String
    getName kh = maybe "" C.keyName (find kh)

    getSlot :: KeyHash -> Int
    getSlot kh = maybe 0 C.hsmSlot (find kh)


withLibrary :: LibraryPath -> (PKCS.Library -> IO a ) -> IO a
withLibrary l = bracket (PKCS.loadLibrary l) PKCS.releaseLibrary

findPrivKey :: String -> HSMSession PKCS.Object
findPrivKey name = find1Obj [PKCS.Class PKCS.PrivateKey, PKCS.Label name, PKCS.Token True]

findPubKey :: String -> HSMSession PKCS.Object
findPubKey name = find1Obj [PKCS.Class PKCS.PublicKey, PKCS.Label name, PKCS.Token True]

signHsm :: String -> ByteString -> HSMSession Signature
signHsm keyName dat = do
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

runSessionRO :: PKCS.Library -> SlotId -> UserPin -> HSMSession a -> IO a
runSessionRO = runSession' False

runSessionRW :: PKCS.Library -> SlotId -> UserPin -> HSMSession a -> IO a
runSessionRW = runSession' True

runSession' :: Bool -> PKCS.Library -> SlotId -> UserPin -> HSMSession a -> IO a
runSession' writeable lib slotId pin hsms =
  PKCS.withSession lib (unsafeCoerce slotId) writeable
      (\sess -> bracket
          (PKCS.login sess PKCS.User (DBC.pack pin))
          (const $ PKCS.logout sess)
          (pure $ runReaderT hsms sess))

parseTZKey :: String -> HSMSession (ByteString, ByteString)
parseTZKey name = do
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
        Right x -> pure (pubKeyHash x, pubKey x)

-- | TODO: make this more generic to support creating multiple curves
generateKeyPair :: CurveName -> String -> HSMSession (PKCS.Object, PKCS.Object)
generateKeyPair curve name = do
    sess <- ask
    liftIO $ PKCS.generateKeyPair
        (PKCS.simpleMech PKCS.EcdsaKeyPairGen)
        [PKCS.Token True, PKCS.EcdsaParams ecdsaParams, PKCS.Label name]
        [PKCS.Token True, PKCS.Label name]
        sess

    where ecdsaParams = encodeASN1' DER [OID (ASN1.curveToEcParams curve)]
