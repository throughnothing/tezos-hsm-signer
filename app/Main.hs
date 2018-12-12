module Main where

import System.IO
import Control.Exception

import qualified HSM as HSM
import qualified Web as Web
import qualified Config as C

main :: IO ()
main = do
  config <- C.readConfig "config.yaml"
  putStrLn $ "Loaded Config: " ++ (show config)
  pin <- getPin
  let lib = C.libPath (C.hsm config)
      port = C.port (C.server config) in do
    Web.serveSignerAPI port (HSM.hsmInterpreterIO lib pin) config

-- | TODO: Actually get PIN from console / user input
getPin :: IO String
getPin = pure "12345"


-- | To generate a new secp521r1 key:
-- | HSM.generatesecp421r1Key {libPath} {slotId} {userPin} {keyName}