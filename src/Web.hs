{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}

module Web (serveSignerAPI) where

import Servant
import Servant.API
import Network.Wai
import Network.Wai.Handler.Warp
import Data.ByteString.Char8 (pack, unpack, ByteString)

import Control.Monad (join)
import Control.Monad.IO.Class (liftIO)
import Control.Exception (handle)
import Data.Traversable (sequence)

import qualified Config as C
import qualified HSM as HSM


type SignerAPI = "keys" :> Get '[PlainText] String
  :<|> "keys" :> Capture "keyHash" String :> Get '[PlainText] String
  :<|> "keys" :> Capture "keyHash" String :> Post '[PlainText] String
  :<|> "lock" :> Get '[PlainText] String

server :: HSM.HSM IO -> C.Config -> Server SignerAPI
server hsm config = keys
  :<|> getKeyHash
  :<|> signMessage
  :<|> lock
  where
    keys :: Handler String
    keys = return "Keys"

    getKeyHash :: String -> Handler String
    getKeyHash hash = return $ case (C.findKeyByHash hash (C.keys config)) of
      Nothing -> "Address not found."
      Just k -> "Address Found: " ++ (show k)

    -- | TODO: Get request body in quotes
    signMessage :: String -> Handler String
    signMessage hash = case configKeyM of
        Nothing -> throwError err404
        Just k -> do
          signMaybe <- liftIO $ HSM.sign hsm (C.hsmSlot k) (C.keyName k) (pack "TESTDATA")
          case signMaybe of
            Nothing -> throwError err500
            Just s -> return $ show s
      where
        configKeyM = C.findKeyByHash hash (C.keys config)

    lock :: Handler String
    lock = return "Goodnight."


-- | Servant Boilerplate
signerAPI :: Proxy SignerAPI
signerAPI = Proxy

signerApp :: HSM.HSM IO -> C.Config -> Application
signerApp h c = serve signerAPI $ server h c

serveSignerAPI :: Int -> HSM.HSM IO -> C.Config -> IO ()
serveSignerAPI port h c = run port $ logMiddleware $ signerApp h c

logMiddleware :: Middleware
logMiddleware innerApp request respond = do
  -- | TODO: Structure this log better
  putStrLn $ show request
  innerApp request respond