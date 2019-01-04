{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
module Tezos.Types
  ( TzCmd
  , Prefix(..)
  , mkTzCmd
  , mkTzCmdFromStr
  , toBS
  , toHexStr
  ) where

import Data.Aeson (FromJSON(..), ToJSON(..), Value(..))
import Data.ByteString (ByteString, unpack, pack)
import Data.Char (digitToInt, intToDigit, isHexDigit)
import Data.String (fromString)
import GHC.Generics (Generic)

import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteArray as BA
import qualified Data.Text as DT

newtype Prefix = Prefix ByteString deriving (Show, Generic)

newtype TzCmd = TzCmd ByteString deriving (Show, Generic)
instance FromJSON TzCmd where
  parseJSON (Data.Aeson.String s) =
    case mkTzCmdFromText s of
      Nothing -> fail "Invalid Command String"
      Just tz -> pure tz
  parseJSON _ = fail "Invalid Command String"

instance ToJSON TzCmd where
    toJSON (TzCmd bs) = String $ (fromString . BSC.unpack) bs

mkTzCmd :: ByteString -> Maybe TzCmd
mkTzCmd i = case first of
  []  -> Nothing
  (x:_) ->
    if (x == 1 || x == 2)
    then Just $ TzCmd i
    else Nothing
  where first = Data.ByteString.unpack (BA.take 1 i)

mkTzCmdFromStr :: String -> Maybe TzCmd
mkTzCmdFromStr i
  | (snd dec) == "" && i /= "" = Just . TzCmd $ fst dec
  | otherwise = Nothing
  where
    dec = B16.decode $ BSC.pack i

mkTzCmdFromText :: DT.Text -> Maybe TzCmd
mkTzCmdFromText t = mkTzCmdFromStr $ DT.unpack t

toBS :: TzCmd -> ByteString
toBS (TzCmd i) = i

toHexStr :: TzCmd -> String
toHexStr (TzCmd bs) = BSC.unpack $ B16.encode bs
