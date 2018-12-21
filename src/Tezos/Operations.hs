module Tezos.Operations (sign) where

import Data.ByteString (ByteString)

import Encoding (b58Check)
import Hash (toBS, blake2b256)
import Tezos.Constants (sigPrefix)

import qualified Crypto.Types as CT
import qualified Tezos.Types as TT

-- | TODO: Make this work for multiple Curves

sign :: Functor f => (ByteString -> f CT.Signature) -> TT.TzCmd -> f ByteString
sign f tz = b58c <$> f (toBS $ blake2b256 (TT.toBS tz))
  where b58c (CT.Signature curve sig) = b58Check (sigPrefix curve) sig
