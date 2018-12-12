{-# LANGUAGE DeriveGeneric #-}
module Config where

import Data.Yaml
import Data.List
import GHC.Generics
import Foreign.C.Types (CULong)
import Data.Word


data ServerConfig = ServerConfig { port :: Int } deriving (Show, Generic)
instance FromJSON ServerConfig

data HsmConfig = HsmConfig { libPath :: FilePath } deriving (Show, Generic)
instance FromJSON HsmConfig

data KeysConfig = KeysConfig
  { keyName :: String
  , publicKeyHash :: String
  , publicKey :: String
  , hsmSlot :: Word64
  } deriving (Show, Generic)
instance FromJSON KeysConfig

data Config = Config
  { server :: ServerConfig
  , hsm :: HsmConfig 
  , keys :: [KeysConfig]
  } deriving (Show, Generic)
instance FromJSON Config

readConfig :: FilePath -> IO Config
readConfig = decodeFileThrow

findKeyByHash :: String -> [KeysConfig] -> Maybe KeysConfig
findKeyByHash h xs = find (\x -> h == (publicKeyHash x)) xs