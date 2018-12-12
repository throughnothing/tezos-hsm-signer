{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-#LANGUAGE OverloadedStrings #-}
module Web (serveSignerAPI) where

import Control.Monad.IO.Class (liftIO)
import Servant
import Servant.API
import Network.Wai
import Network.Wai.Handler.Warp
import Data.ByteString.Char8 (pack, unpack, ByteString)

import qualified Config as C
import qualified HSM

type SignerAPI =
  "auhtorized_keys" :> Get '[PlainText, JSON] String
  :<|> "keys" :> Get '[PlainText, JSON] String
  :<|> "keys" :> Capture "keyHash" String :> Get '[PlainText, JSON] String
  :<|> "keys" :> Capture "keyHash" String :> ReqBody '[PlainText] String :> Post '[PlainText, JSON] String
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

    getKeyHash :: String -> Handler String
    getKeyHash hash = do
      hasKey <- liftIO $ HSM.hasKey hsm hash
      if hasKey then return $ "\"" ++ hash ++ "\"" else throwError err404

    -- | TODO: Get request body in quotes
    signMessage :: String -> String -> Handler String
    signMessage hash dat = do
        signMaybe <- liftIO $ HSM.sign hsm hash (pack dat)
        case signMaybe of
          Nothing -> throwError err404
          Just s -> return $ show s

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