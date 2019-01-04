module Tezos.Constants
  ( pkPrefix
  , pkhPrefix
  , sigPrefix
  , skPrefix
  ) where

import Data.ByteString (pack, ByteString)
import Data.Word (Word8)

import Tezos.Types ()
import Crypto.Types (CurveName(..))

-- | All Prefixes in this file taken from:
-- | https://gitlab.com/tezos/tezos/blob/master/src/lib_crypto/base58.ml

sigPrefix :: CurveName -> ByteString
sigPrefix P256 = _p [54, 240, 44, 52]
sigPrefix SECP256K1 = _p [13, 115, 101, 019, 063]
sigPrefix ED25519 = _p [9, 245, 205, 134, 018]

pkhPrefix :: CurveName -> ByteString
pkhPrefix P256 = _p [6,161,164]
pkhPrefix SECP256K1 = _p [6, 161, 161]
pkhPrefix ED25519 = _p [6, 161, 159]

pkPrefix :: CurveName -> ByteString
pkPrefix P256 = _p [3,178,139,127]
pkPrefix SECP256K1 = _p [3, 254, 226, 86]
pkPrefix ED25519 = _p [13, 15, 37, 217]

skPrefix :: CurveName -> ByteString
skPrefix P256 = _p [16, 81, 238, 189]
skPrefix SECP256K1 = _p [17, 162, 224, 201]
skPrefix ED25519 = _p [13, 15, 58, 7]


_p :: [Word8] -> ByteString
_p = pack
