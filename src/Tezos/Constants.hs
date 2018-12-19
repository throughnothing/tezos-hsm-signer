module Tezos.Constants where

import Data.ByteString (ByteString, pack)

-- | Prefix bytes for P2Sig in Tezos
-- |https://gitlab.com/tezos/tezos/blob/master/src/lib_crypto/base58.ml#L354
p256SigPrefix :: ByteString
p256SigPrefix = pack [54, 240, 44, 52]

-- | https://gitlab.com/tezos/tezos/blob/master/src/lib_crypto/base58.ml#L328
-- | P256 Secret Key Prefix
p256SKPrefix :: ByteString
p256SKPrefix = pack [16, 81, 238, 189]

-- | https://gitlab.com/tezos/tezos/blob/master/src/lib_crypto/base58.ml#L328
-- | P256 Public Key Prefix
p256PKPrefix :: ByteString
p256PKPrefix = pack [3,178,139,127]

-- \009\048\057\115\171
-- | P256 Encrypted Secret Key Prefix
p256ESKPrefix :: ByteString
p256ESKPrefix = pack [9,48,57,115,171]

-- | This is to generate generates tz3 addresses
p256PKHPrefix :: ByteString
p256PKHPrefix = pack [6,161,164]