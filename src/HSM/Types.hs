module HSM.Types where

import Control.Exception (Exception)
import Data.ByteString.Char8 (ByteString)

import Crypto.Types (CurveName, Signature, PublicKey)

import qualified System.Crypto.Pkcs11 as PKCS

-- | The main data type for HSM Interactions
data HSM f = HSM
    { sign   :: KeyHash -> ByteString -> f Signature
    , getPublicKey :: KeyHash -> f PublicKey
    }

type KeyHash = String


-- | Errors 

newtype ObjectNotFound = ObjectNotFound String deriving (Show)
instance Exception ObjectNotFound

newtype ParseError = ParseError String deriving (Show)
instance Exception ParseError

newtype UnknownEcdsaParams = UnknownEcdsaParams String deriving (Show)
instance Exception UnknownEcdsaParams