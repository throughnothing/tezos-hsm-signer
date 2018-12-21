module HSM.Types where

import Control.Exception (Exception)
import Data.ByteString.Char8 (ByteString)

import Crypto.Types (CurveName(..))
import Tezos.Types (Signature)

import qualified System.Crypto.Pkcs11 as PKCS

-- | The main data type for HSM Interactions
data HSM f = HSM
    { sign   :: KeyHash -> ByteString -> f Signature
    , getPublicKey :: KeyHash -> f PublicKey
    }

type PubKey = PKCS.Object
type PrivKey = PKCS.Object
type SlotId  = Int

type LibraryPath = String
type UserPin = String
type KeyHash = String
type KeyName = String
type Data = String
type SignedMessage = ByteString
type PublicKey = String

newtype ObjectNotFound = ObjectNotFound String deriving (Show)
instance Exception ObjectNotFound

newtype ParseError = ParseError String deriving (Show)
instance Exception ParseError

newtype UnknownEcdsaParams = UnknownEcdsaParams String deriving (Show)
instance Exception UnknownEcdsaParams