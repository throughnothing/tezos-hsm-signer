{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-#LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module Web (serveSignerAPI) where

import Control.Exception (try)
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON, ToJSON, Value)
import Data.Aeson.Types (emptyObject)
import GHC.Generics (Generic)
import Servant
import Servant.API ()
import Network.Wai
import Network.Wai.Handler.Warp
import Data.ByteString.Char8 (unpack)
import System.Posix.Process (exitImmediately)
import System.Exit (ExitCode(..))

import Crypto.Types ()
import Tezos.Encoding (pubKeyStr)
import Tezos.Operations (sign)
import Tezos.Types (TzCmd)


import qualified HSM
import qualified Network.HTTP.Media  as M


-- | All this is a hack for application/json content-type (without charset) that tezos needs
data JSONSimple

instance Accept JSONSimple where
  contentType _ = "application" M.// "json"

instance ToJSON t => MimeRender JSONSimple t where
  mimeRender _ = mimeRender (Proxy :: Proxy JSON)

instance FromJSON t => MimeUnrender JSONSimple t where
  mimeUnrender _ = mimeUnrender (Proxy :: Proxy JSON)


-- | Request Types
newtype SignatureReq = SignatureReq TzCmd deriving(Show, Generic)
instance FromJSON SignatureReq
instance ToJSON SignatureReq

-- | Response Types
newtype SignatureRes = SignatureRes { signature :: String } deriving (Show, Generic)
instance FromJSON SignatureRes
instance ToJSON SignatureRes

newtype PublicKeyRes = PublicKeyRes { public_key :: String } deriving (Show, Generic)
instance FromJSON PublicKeyRes
instance ToJSON PublicKeyRes

-- | API Type
type SignerAPI =
  "authorized_keys" :> Get '[JSONSimple] Value
  :<|> "keys" :> Get '[JSONSimple] Value
  :<|> "keys" :> Capture "keyHash" String :> Get '[JSONSimple] PublicKeyRes
  :<|> "keys" :> Capture "keyHash" String :> ReqBody '[JSON] SignatureReq :> Post '[JSONSimple] SignatureRes
  :<|> "lock" :> Get '[PlainText, JSON] String

server :: HSM.HSM IO -> Server SignerAPI
server hsm = authorizedKeys
  :<|> keys
  :<|> getPubKey
  :<|> signMessage
  :<|> lock
  where
    authorizedKeys :: Handler Value
    authorizedKeys = return emptyObject

    keys :: Handler Value
    keys = return emptyObject

    getPubKey :: String -> Handler PublicKeyRes
    getPubKey hash = do
      pubKeyE <- liftIO $ try $ HSM.getPublicKey hsm hash
      case pubKeyE of
        Left (HSM.ObjectNotFound _) -> throwError err404
        Right pk -> return $ PublicKeyRes { public_key = pubKeyStr pk }

    signMessage :: String -> SignatureReq -> Handler SignatureRes
    signMessage hash (SignatureReq tzcmd) = do
        signE <- liftIO $ try $ sign (HSM.sign hsm hash) tzcmd
        case signE of
          Left (HSM.ObjectNotFound _) -> throwError err404
          Right s -> return $ SignatureRes { signature = unpack s }

    lock :: Handler String
    lock = liftIO $ do
      print "Goodnight."
      exitImmediately (ExitFailure 11)
      pure ""

signerApp :: HSM.HSM IO -> Application
signerApp h = serve (Proxy :: Proxy SignerAPI) $ server h

serveSignerAPI :: Int -> HSM.HSM IO -> IO ()
serveSignerAPI port h = run port $ logMiddleware $ signerApp h

logMiddleware :: Middleware
logMiddleware innerApp request respond = do
  -- | TODO: Structure the logs better
  print request
  innerApp request respond
