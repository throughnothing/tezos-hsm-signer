module Main where

import qualified HSM
import qualified Web
import qualified Config as C

main :: IO ()
main = do
  config <- C.readConfig "config.yaml"
  putStrLn $ "Loaded Config: " ++ show config
  pin <- getPin
  let lib = C.libPath (C.hsm config)
      port = C.port (C.server config) in
    HSM.withHsmIO lib pin (C.findKeyByHash config) (Web.serveSignerAPI port)

-- | TODO: Actually get PIN from console / user input
getPin :: IO String
getPin = pure "12345"