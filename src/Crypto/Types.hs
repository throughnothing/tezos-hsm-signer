{-# LANGUAGE DeriveGeneric #-}
module Crypto.Types where

import Data.ByteString (ByteString)
import GHC.Generics (Generic)

import qualified Crypto.PubKey.ECC.ECDSA as CE


data CurveName = P256 | SECP256K1 | ED25519 deriving (Show)

data Signature = Signature CurveName ByteString deriving (Show, Generic)

data PublicKey = PublicKey
  { curveName :: CurveName
  , pk :: CE.PublicKey
  } deriving (Show, Generic)