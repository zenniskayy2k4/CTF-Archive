-- File: chall_formatted.hs
-- Đây là phiên bản đã được định dạng lại để dễ đọc và phân tích.

import Control.Monad
import Data.Bits
import Data.Char
import Data.Function
import Data.List
import Data.Set (Set)
import qualified Data.Set as Set
import GHC.Num
import System.IO

-- =============================================================================
-- CÁC HÀM TIỆN ÍCH VÀ HẰNG SỐ
-- =============================================================================

-- Hàm if' chỉ là một cách viết khác cho if-then-else
if' :: Bool -> a -> a -> a
if' c t f = if c then t else f

-- Đây là con số khổng lồ mà kết quả cuối cùng phải bằng
targetNumber :: Integer
targetNumber = 9808081677743135172288409775188158796289815169603605322273727506636905106808987096987267047244859212186619239940023129609388059687300704940688943841969983867118828709966912736034579721516747709253350210

-- =============================================================================
-- CÁC KHỐI LOGIC CHÍNH ĐÃ ĐƯỢC TÁCH RA
-- =============================================================================

-- PHẦN 1: TẠO DÃY SỐ (DÃY TRIBONACCI)
-- Đoạn mã này tạo ra một danh sách vô hạn các số theo quy luật Tribonacci.
-- Bắt đầu bằng [1, 2, 3], số tiếp theo bằng tổng 3 số trước đó.
-- Ví dụ: 1, 2, 3, 6, 11, 20, ...
tribs :: [Integer]
tribs = fix ((1 :) . (2 :) . (3 :) . ap (zipWith (+) . tail . tail) (zipWith (+) =<< tail))

-- PHẦN 2: XÁO TRỘN DỮ LIỆU (PHỨC TẠP NHẤT)
-- Hàm này nhận vào danh sách mã ASCII của flag và thực hiện một loạt
-- các phép biến đổi, xáo trộn rất phức tạp.
-- Nó sử dụng chính danh sách đầu vào, độ dài của nó, và dãy Tribonacci ở trên.
dataMangle :: [Integer] -> [Integer]
dataMangle =
  ap
    ( flip . ((flip . (ap (flip flip ((flip (liftM2 (++) fst . (. snd) . (:)) .) . splitAt) . flip flip (fix . ((ap (flip if' [([])] . null) . ap (ap (if' . (1 ==) . length) (return . return . head)) . (`ap` tail) . (. head) . flip) .) . (. (((.) . (>>=)) .)) . flip flip . (((`ap` (enumFromTo 0 . length)) . (map .)) .) . flip . (flip .) . flip) . ((.) .) . flip flip (fix (ap (flip if' 0 . null) . flip flip ((1 +) . fromIntegral . integerLogBase 3) . flip flip (. fromIntegral) . (ap .) . flip flip ((. (3 ^)) . (*)) . ((flip . (flip .)) .) . (`ap` tail) . ((flip . ((flip . (flip .)) .)) .) . (. head) . flip . ((flip . ((flip . (flip .)) .)) .) . flip . ((flip . ((flip . (ap .)) .)) .) . ap ((.) . ap . (liftM2 (ap . ((.) .) . flip (if' . (0 ==)) . (3 +)) .) . flip flip 2 . (flip .) . flip (.)) (ap (ap . (((.) . flip . ((ap . ((+) .) . liftM2 (+) toInteger) .)) .) . flip (flip . ((.) .))) . (. ap (+)) . flip . ((flip . ((.) .)) .) . flip (.)))) . (flip .) . flip flip (fix ((ap (flip if' ([]) . null) .) . (`ap` splitAt) . (((.) . liftM2 (:) fst) .) . flip flip snd . ((.) .))) . ((flip . ((flip . flip ((.) . ap (.) (map . (. map fromIntegral)))) .) . flip ((.) . flip zipWith [0..] . flip . ((!!) .))) .) . flip . flip id) .)) .)
    (ap ((.) . flip . (flip .) . (.) . (.) . map . (!!)) (map . (fromIntegral .) . flip rem . toInteger . length))
    length
    tribs

uniqueFilter :: Ord a => [a] -> [a]
uniqueFilter =
  (`ap` flip (fix (ap ((.) . flip if' ([]) . (([]) ==)) . (`ap` (Set.insert . head)) . (((.) . ap (:)) .) . (. tail))) Set.empty)
    . zipWith . flip ((.) . (,))
    . flip ((<) . length)

finalConversion :: [Integer] -> Integer
finalConversion =
  (map fst . takeWhile snd . fix . const . ap ((:) . flip (,) True . fst . head) (ap (zipWith (flip ((,) . fst) . snd)) tail))

checkFlag :: [Int] -> Bool
checkFlag =
  (targetNumber ==)
    . finalConversion
    . uniqueFilter
    . dataMangle
    . map toInteger

main :: IO ()
main = do
  putStr "Input flag: "
  hFlush stdout
  flag <- getLine
  putStrLn $ if checkFlag (map ord flag) then "Correct" else "Wrong"