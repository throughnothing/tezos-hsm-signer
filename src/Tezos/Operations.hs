module Tezos.Operations (sign) where

import Data.ByteString (ByteString)

import Encoding (b58Check)
import Hash (toBS, blake2b256)
import Tezos.Constants (p256SigPrefix)

import qualified Tezos.Types as TT

sign :: Functor f => (ByteString -> f ByteString) -> TT.TzCmd -> f ByteString
sign f tz = b58Check p256SigPrefix <$> f (toBS $ blake2b256 (TT.toBS tz))
