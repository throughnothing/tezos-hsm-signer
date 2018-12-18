module Tezos.Constants where

import Data.ByteString (ByteString, pack)

-- | Leading bytes for P2Sig in Tezos
-- | https://github.com/tacoinfra/remote-signer/blob/master/src/remote_signer.py#L26
-- p256SigPrefix :: ByteString
-- p256SigPrefix = pack [0x36,0xF0,0x2C,0x34]

p256SigPrefix :: ByteString
p256SigPrefix = pack [54, 240, 44, 52]