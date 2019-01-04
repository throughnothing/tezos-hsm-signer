module Tezos.Operations (sign) where

import Data.ByteString (ByteString)

import Encoding (b58Check)
import Hash (toBS, blake2b256)
import Tezos.Constants (sigPrefix)

import qualified Crypto.Types as CT
import qualified Tezos.Types as TT

sign :: Functor f => (ByteString -> f CT.Signature) -> TT.TzCmd -> f ByteString
sign f tz = b58c <$> f (blake2b tzBs)
  where
    b58c (CT.Signature curve sig) = b58Check (sigPrefix curve) sig
    tzBs = TT.toBS tz
    blake2b = toBS . blake2b256
