{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-#LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
module Web (serveSignerAPI) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON, ToJSON)
import GHC.Generics (Generic)
import Servant
import Servant.API
import Network.Wai
import Network.Wai.Handler.Warp
import Data.ByteString.Char8 (pack, unpack, ByteString)

import qualified Config as C
import qualified HSM
import qualified Encodings as E


type SignerAPI =
  "auhtorized_keys" :> Get '[PlainText, JSON] String
  :<|> "keys" :> Get '[PlainText, JSON] String
  :<|> "keys" :> Capture "keyHash" String :> Get '[JSON] PublicKeyRes
  :<|> "keys" :> Capture "keyHash" String :> ReqBody '[JSON] String :> Post '[JSON] SignatureRes
  :<|> "lock" :> Get '[PlainText, JSON] String

newtype SignatureRes = SignatureRes { signature :: E.Base58String } deriving (Show, Generic)
instance FromJSON SignatureRes
instance ToJSON SignatureRes

newtype PublicKeyRes = PublicKeyRes { public_key :: String } deriving (Show, Generic)
instance FromJSON PublicKeyRes
instance ToJSON PublicKeyRes


server :: HSM.HSM IO -> Server SignerAPI
server hsm = authorizedKeys
  :<|> keys
  :<|> getKeyHash
  :<|> signMessage
  :<|> lock

  where
    authorizedKeys :: Handler String
    authorizedKeys = return "{}"

    keys :: Handler String
    keys = return "{}"

    getKeyHash :: String -> Handler PublicKeyRes
    getKeyHash hash = do
      pubKey <- liftIO $ HSM.getPublicKey hsm hash
      case pubKey of
        Nothing -> throwError err404
        Just s -> return $ PublicKeyRes { public_key = s }

    signMessage :: String -> String -> Handler SignatureRes
    signMessage hash dat = 
        case E.mkHexString dat of
          Nothing -> throwError err400
          Just parsedData -> do
            signMaybe <- liftIO $ HSM.sign hsm hash parsedData
            case signMaybe of
              Nothing -> throwError err404
              Just s -> return $ SignatureRes { signature = s }

    -- | Todo: Actually make this ext...
    lock :: Handler String
    lock = return "Goodnight."

signerApp :: HSM.HSM IO -> Application
signerApp h = serve (Proxy :: Proxy SignerAPI) $ server h

-- | TODO: Don't requires HSM IO specifically, require HSM f + natrual transform to IO
serveSignerAPI :: Int -> HSM.HSM IO -> IO ()
serveSignerAPI port h = run port $ logMiddleware $ signerApp h

logMiddleware :: Middleware
logMiddleware innerApp request respond = do
  -- | TODO: Structure this log better
  print request
  innerApp request respond