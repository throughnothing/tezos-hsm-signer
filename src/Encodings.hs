{-# LANGUAGE DeriveGeneric #-}
module Encodings where

import Data.Aeson (FromJSON, ToJSON)
import GHC.Generics (Generic)
import Data.Char (isHexDigit, digitToInt, intToDigit, toUpper)
import Crypto.Hash.BLAKE2.BLAKE2b (hash)
import Data.ByteString.Base58 (decodeBase58, encodeBase58, bitcoinAlphabet)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

newtype Base58String = Base58String String deriving (Show, Generic)
instance ToJSON Base58String
instance FromJSON Base58String

newtype HexString = HexString String deriving (Show, Generic)

mkHexString :: String -> Maybe HexString
mkHexString s = if all isHexDigit s
    then Just $ HexString s
    else Nothing

strToHex :: HexString -> BS.ByteString
strToHex (HexString s) = BS.pack $ fromIntegral . digitToInt <$> s

blake2b :: BS.ByteString -> BS.ByteString
blake2b = hash 32 mempty

toHexStr :: BS.ByteString -> HexString
toHexStr bs = HexString $ intToDigit . fromIntegral <$> BS.unpack bs

toBase58Str :: BS.ByteString -> Base58String
toBase58Str bs = Base58String $ BSC.unpack $ encodeBase58 bitcoinAlphabet bs

toBase58 :: BS.ByteString -> BS.ByteString
toBase58 = encodeBase58 bitcoinAlphabet

base58ToHex :: Base58String -> Maybe HexString
base58ToHex (Base58String s) = toHexStr <$> decodeBase58 bitcoinAlphabet (BSC.pack s)

-- | Leading bytes for P2Sig
-- | https://github.com/tacoinfra/remote-signer/blob/master/src/remote_signer.py#L26
p256Signature :: BS.ByteString
p256Signature = BS.pack [0x36,0xF0,0x2C,0x34]