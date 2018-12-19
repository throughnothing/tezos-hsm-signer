module Main where

import qualified HSM.IO as HSMIO
import qualified Web
import qualified Config as C
import qualified Pin

main :: IO ()
main = do
  config <- C.readConfig "config.yaml"
  putStrLn $ "Loaded Config: " ++ show config
  pin <- Pin.getPin "HSM User Pin:"
  let lib = C.libPath (C.hsm config)
      port = C.port (C.server config) in
    HSMIO.withHsmIO lib pin (C.findKeyByHash config) (Web.serveSignerAPI port)