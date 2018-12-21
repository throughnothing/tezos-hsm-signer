import Test.Hspec
import Test.QuickCheck (property)
import Test.QuickCheck.Modifiers (Positive(..))  

import Data.Char (intToDigit, toLower, isHexDigit)
import Data.Maybe (isNothing, isJust)

import qualified Crypto.Types as CT
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified HSM.IO.Internal as HSM
import qualified Tezos.Types as TT

main :: IO ()
main = tezosTypesTests
  
tezosTypesTests :: IO ()
tezosTypesTests = 
  hspec $ do
    describe "mkTzCmd" $
      it "only allows ByteStrings starting with 1 or 2" $ property $
        \x -> let res = TT.mkTzCmd (BS.pack x) in
          if not (null x) && (head x == 1 || head x == 2)
          then (BS.unpack . TT.toBS <$> res) == Just x
          else isNothing res

    describe "mkTzCmdFromStr" $
      it "only allows Hex Strings starting with 1 or 2" $ property $
        \x ->
          let res = TT.mkTzCmdFromStr x
              isValidHex = all isHexDigit x in
          if isValidHex && x /= "" && (head x == '1' || head x == '2')
          then (TT.toStr <$> res) == Just (toLower <$> x)
          else isNothing res

-- | Notes:

  -- -- | Generate a new P256 ECDSA KeyPair
  -- newKey <- HSM.withLibrary "/usr/local/lib/softhsm/libsofthsm2.so" $
  --   \l -> HSM.runSessionRW l 1165926823 "12345" $ HSM.generateKeyPair CT.SECP256K1 "Test Key LOL 2"
  -- print newKey

-- | Parse a PubKey to Tezos format (P256 only atm)
-- pkh <- HSM.withLibrary library $
--   \l -> HSM.runSessionRO l slotId pin $ HSM.parseTZKey kName
-- print pkh
