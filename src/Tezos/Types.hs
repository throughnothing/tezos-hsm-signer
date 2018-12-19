{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
module Tezos.Types
  ( TzCmd
  , mkTzCmd
  , toBS
  )where

import Data.Aeson (FromJSON(..), ToJSON(..), Value(..))
import Data.ByteString (ByteString)
import Data.Char (digitToInt)
import Data.Maybe (fromMaybe)
import Data.String (fromString)
import GHC.Generics (Generic)

import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteArray as BA
import qualified Data.Text as DT

newtype TzCmd = TzCmd ByteString deriving (Show, Generic)
instance FromJSON TzCmd where
  parseJSON (Data.Aeson.String s) =
    case mkTzCmd ((BSC.pack . DT.unpack) s) of
      Nothing -> fail "Invalid Command String"
      Just tz -> pure tz

instance ToJSON TzCmd where
    toJSON (TzCmd bs) = String $ (fromString . BSC.unpack) bs

mkTzCmd :: ByteString -> Maybe TzCmd
mkTzCmd i = case first of
  [] -> Nothing
  (x:xs) -> if x == 1 || x == 2
    then Just $ TzCmd i
    else Nothing
  where first = digitToInt <$> BSC.unpack (BA.take 1 i)

toBS :: TzCmd -> ByteString
toBS (TzCmd i) = i