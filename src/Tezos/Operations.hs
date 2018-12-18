module Tezos.Operations (sign) where

import Data.ByteString (ByteString)

import Encoding (b58Check)
import Hash (toBS, blake2b256)
import Tezos.Constants (p256SigPrefix)

-- TODO: Validate Preamble, make sure it's not already a signed message, etc.
sign :: Functor f => (ByteString -> f ByteString) -> ByteString -> f ByteString
sign f i = b58Check p256SigPrefix <$> f (toBS $ blake2b256 i)
