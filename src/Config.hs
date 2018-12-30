{-# LANGUAGE DeriveGeneric #-}
module Config where

import Control.Exception (throw)
import Data.Yaml (decodeFileEither, FromJSON)
import GHC.Generics (Generic)

newtype ServerConfig = ServerConfig { port :: Int } deriving (Show, Generic)
instance FromJSON ServerConfig

newtype HsmConfig = HsmConfig { libPath :: FilePath } deriving (Show, Generic)
instance FromJSON HsmConfig

data KeysConfig = KeysConfig
  { keyName :: String
  , hsmSlot :: Int
  } deriving (Show, Generic)
instance FromJSON KeysConfig

data Config = Config
  { server :: ServerConfig
  , hsm :: HsmConfig 
  , keys :: [KeysConfig]
  } deriving (Show, Generic)
instance FromJSON Config

readConfig :: FromJSON a => FilePath -> IO a
readConfig f = decodeFileEither f >>= handle
  where
    handle (Left e) = pure $ throw e
    handle (Right c) = pure c
