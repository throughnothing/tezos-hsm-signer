module Pin where

import System.IO (hFlush, stdout, stdin, hGetEcho, hSetEcho)
import Control.Exception (bracket_)

getPin :: String -> IO String
getPin prompt = do
  putStr prompt
  hFlush stdout
  pass <- withEcho False getLine
  putChar '\n'
  case pass of
    "" -> getPin prompt
    _  -> return pass

withEcho :: Bool -> IO a -> IO a
withEcho echo action = do
  old <- hGetEcho stdin
  bracket_ (hSetEcho stdin echo) (hSetEcho stdin old) action