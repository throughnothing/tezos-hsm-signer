module HSM.Types where

import Control.Exception (Exception)
import Data.ByteString.Char8 (ByteString)

import qualified System.Crypto.Pkcs11 as PKCS

type PubKey = PKCS.Object
type PrivKey = PKCS.Object
type SlotId  = PKCS.SlotId

type LibraryPath = String
type UserPin = String
type KeyHash = String
type KeyName = String
type Data = String
type SignedMessage = ByteString
type PublicKey = String

data KeyNotFound = KeyNotFound deriving (Show)
instance Exception KeyNotFound

newtype ParseError = ParseError String deriving (Show)
instance Exception ParseError