{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-#LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
module Web (serveSignerAPI) where

import Control.Exception (try)
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON, ToJSON)
import GHC.Generics (Generic)
import Servant
import Servant.API
import Network.Wai
import Network.Wai.Handler.Warp
import Data.ByteString.Char8 (pack, unpack, ByteString)
import System.Posix.Process (exitImmediately)
import System.Exit (ExitCode(..))
import Tezos.Operations (sign)

import qualified Config as C
import qualified HSM


-- | Request Types
newtype SignatureReq = SignatureReq String deriving(Show, Generic)
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
  "auhtorized_keys" :> Get '[JSON] String
  :<|> "keys" :> Get '[PlainText, JSON] String
  :<|> "keys" :> Capture "keyHash" String :> Get '[JSON] PublicKeyRes
  :<|> "keys" :> Capture "keyHash" String :> ReqBody '[JSON] SignatureReq :> Post '[JSON] SignatureRes
  :<|> "lock" :> Get '[PlainText, JSON] String

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
      pubKey <- liftIO $ try $ HSM.getPublicKey hsm hash
      case pubKey of
        Left HSM.KeyNotFound -> throwError err404
        Right s -> return $ PublicKeyRes { public_key = s }

    signMessage :: String -> SignatureReq -> Handler SignatureRes
    signMessage hash (SignatureReq dat) = do
        signE <- liftIO $ try $ sign (HSM.sign hsm hash) (pack dat)
        case signE of
          Left HSM.KeyNotFound -> throwError err404
          Right s -> return $ SignatureRes { signature = unpack s }

    lock :: Handler String
    lock = liftIO $ do
      print "Goodnight."
      exitImmediately (ExitFailure 11)
      pure ""

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