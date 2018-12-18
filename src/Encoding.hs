module Encoding where

import Data.ByteString (ByteString)
import Data.ByteString.Base58 (encodeBase58, bitcoinAlphabet)
import Data.ByteArray (pack, unpack)

import Hash (sha256)

-- | Modeled after: https://github.com/wzbg/base58check/blob/master/index.js#L13
b58Check :: ByteString -> ByteString -> ByteString
b58Check prefix bs = encodeB58 $ dat `mappend` dblShaFirst4
    where
        dat = prefix `mappend` bs
        dblShaFirst4 = pack $ take 4 $ unpack dblSha256
        dblSha256 = sha256 $ sha256 dat

encodeB58 :: ByteString -> ByteString
encodeB58 = encodeBase58 bitcoinAlphabet