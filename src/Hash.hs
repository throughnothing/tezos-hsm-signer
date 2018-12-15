module Hash where

import Crypto.Hash (hash, Digest)
import Crypto.Hash.Algorithms (Blake2b_160, Blake2b_256, SHA256)
import Data.ByteArray (ByteArrayAccess, convert)
import Data.ByteString (ByteString)

blake2b160 :: ByteArrayAccess a => a -> Digest Blake2b_160
blake2b160 = hash

blake2b256 :: ByteArrayAccess a => a -> Digest Blake2b_256
blake2b256 = hash

sha256 :: ByteArrayAccess a => a -> Digest SHA256
sha256 = hash

toBS :: Digest a -> ByteString
toBS = convert