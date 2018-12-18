module Tezos.Constants where

import Data.ByteString (ByteString, pack)

-- | Prefix bytes for P2Sig in Tezos
-- |https://gitlab.com/tezos/tezos/blob/master/src/lib_crypto/base58.ml#L354
p256SigPrefix :: ByteString
p256SigPrefix = pack [54, 240, 44, 52]