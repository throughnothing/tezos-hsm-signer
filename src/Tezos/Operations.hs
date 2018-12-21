module Tezos.Operations (sign) where

import Data.ByteString (ByteString)

import Encoding (b58Check)
import Hash (toBS, blake2b256)
import Tezos.Constants (sigPrefix)

import qualified Tezos.Types as TT

-- | TODO: Make this work for multiple Curves

sign :: Functor f => (ByteString -> f ByteString) -> TT.TzCmd -> f ByteString
sign f tz = b58Check (sigPrefix TT.P256) <$> f (toBS $ blake2b256 (TT.toBS tz))
