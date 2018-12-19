{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
module Tezos.Types
  ( TzCmd
  , mkTzCmd
  , mkTzCmdFromStr
  , toBS
  , toStr
  )where

import Data.Aeson (FromJSON(..), ToJSON(..), Value(..))
import Data.ByteString (ByteString, unpack, pack)
import Data.Char (digitToInt, intToDigit, isHexDigit)
import Data.Maybe (fromMaybe)
import Data.String (fromString)
import GHC.Generics (Generic)

import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteArray as BA
import qualified Data.Text as DT

newtype TzCmd = TzCmd ByteString deriving (Show, Generic)
instance FromJSON TzCmd where
  parseJSON (Data.Aeson.String s) =
    case mkTzCmdFromText s of
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
  where first = Data.ByteString.unpack (BA.take 1 i)

mkTzCmdFromStr :: String -> Maybe TzCmd
mkTzCmdFromStr i 
  | isValidHex = mkTzCmd $  Data.ByteString.pack $ fromIntegral . digitToInt <$> i
  | otherwise = Nothing
   where isValidHex = foldl (\a c -> a && isHexDigit c) True i

mkTzCmdFromText :: DT.Text -> Maybe TzCmd
mkTzCmdFromText t = mkTzCmdFromStr $ DT.unpack t

toBS :: TzCmd -> ByteString
toBS (TzCmd i) = i

toStr :: TzCmd -> String
toStr t@(TzCmd i) = intToDigit . fromIntegral <$> str
  where str = Data.ByteString.unpack $ toBS t