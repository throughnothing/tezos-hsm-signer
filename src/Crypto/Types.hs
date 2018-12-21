{-# LANGUAGE DeriveGeneric #-}
module Crypto.Types where

import Data.ByteString (ByteString)
import GHC.Generics (Generic)

import qualified Crypto.PubKey.ECC.ECDSA as CTE


data CurveName = P256 | SECP256K1 deriving (Show)

data Signature = Signature CurveName ByteString deriving (Show, Generic)

data PublicKey = PublicKey
  { curveName :: CurveName
  , pk :: CTE.PublicKey
  } deriving (Show, Generic)