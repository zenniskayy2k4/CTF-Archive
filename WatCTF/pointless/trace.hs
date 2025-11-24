import Data.Char
import Data.Set (Set)
import qualified Data.Set as Set
import Data.List
import Data.Bits
import GHC.Num
import System.IO
import Data.Function
import Control.Monad
import Debug.Trace -- Thư viện để "trace" (theo dõi) giá trị

if' c t f = if c then t else f

-- Hàm checkFlag gốc
checkFlag = (9808081677743135172288409775188158796289815169603605322273727506636905106808987096987267047244859212186619239940023129609388059687300704940688943841969983867118828709966912736034579721516747709253350210 ==) . flip (flip flip (((map fst . takeWhile snd . fix . const . ap ((:) . flip (,) True . fst . head) (ap (zipWith (flip ((,) . fst) . snd)) tail)) .) . (`ap` flip (fix (ap ((.) . flip if' ([]) . (([]) ==)) . (`ap` (Set.insert . head)) . (((.) . ap (:)) .) . (. tail))) Set.empty) . zipWith . flip ((.) . (,)) . flip ((<) . length)) . ap (flip . ((flip . (ap (flip flip ((flip (liftM2 (++) fst . (. snd) . (:)) .) . splitAt) . flip flip (fix . ((ap (flip if' [([])] . null) . ap (ap (if' . (1 ==) . length) (return . return . head)) . (`ap` tail) . (. head) . flip) .) . (. (((.) . (>>=)) .)) . flip flip . (((`ap` (enumFromTo 0 . length)) . (map .)) .) . flip . (flip .) . flip) . ((.) .) . flip flip (fix (ap (flip if' 0 . null) . flip flip ((1 +) . fromIntegral . integerLogBase 3) . flip flip (. fromIntegral) . (ap .) . flip flip ((. (3 ^)) . (*)) . ((flip . (flip .)) .) . (`ap` tail) . ((flip . ((flip . (flip .)) .)) .) . (. head) . flip . ((flip . ((flip . (flip .)) .)) .) . flip . ((flip . ((flip . (ap .)) .)) .) . ap ((.) . ap . (liftM2 (ap . ((.) .) . flip (if' . (0 ==)) . (3 +)) .) . flip flip 2 . (flip .) . flip (.)) (ap (ap . (((.) . flip . ((ap . ((+) .) . liftM2 (+) toInteger) .)) .) . flip (flip . ((.) .))) . (. ap (+)) . flip . ((flip . ((.) .)) .) . flip (.)))) . (flip .) . flip flip (fix ((ap (flip if' ([]) . null) .) . (`ap` splitAt) . (((.) . liftM2 (:) fst) .) . flip flip snd . ((.) .))) . ((flip . ((flip . flip ((.) . ap (.) (map . (. map fromIntegral)))) .) . flip ((.) . flip zipWith [0..] . flip . ((!!) .))) .) . flip . flip id) .)) .) . ap ((.) . flip . (flip .) . (.) . (.) . map . (!!)) (map . (fromIntegral .) . flip rem . toInteger . length)) length) (fix ((1 :) . (2 :) . (3 :) . ap (zipWith (+) . tail . tail) (zipWith (+) =<< tail)))


-- Chúng ta tách phần tạo danh sách số ra để trace
-- Đây là toàn bộ hàm lớn, chỉ bỏ đi phần so sánh cuối cùng `(TARGET ==)`
generateNumberList = flip (flip flip (((map fst . takeWhile snd . fix . const . ap ((:) . flip (,) True . fst . head) (ap (zipWith (flip ((,) . fst) . snd)) tail)) .) . (`ap` flip (fix (ap ((.) . flip if' ([]) . (([]) ==)) . (`ap` (Set.insert . head)) . (((.) . ap (:)) .) . (. tail))) Set.empty) . zipWith . flip ((.) . (,)) . flip ((<) . length)) . ap (flip . ((flip . (ap (flip flip ((flip (liftM2 (++) fst . (. snd) . (:)) .) . splitAt) . flip flip (fix . ((ap (flip if' [([])] . null) . ap (ap (if' . (1 ==) . length) (return . return . head)) . (`ap` tail) . (. head) . flip) .) . (. (((.) . (>>=)) .)) . flip flip . (((`ap` (enumFromTo 0 . length)) . (map .)) .) . flip . (flip .) . flip) . ((.) .) . flip flip (fix (ap (flip if' 0 . null) . flip flip ((1 +) . fromIntegral . integerLogBase 3) . flip flip (. fromIntegral) . (ap .) . flip flip ((. (3 ^)) . (*)) . ((flip . (flip .)) .) . (`ap` tail) . ((flip . ((flip . (flip .)) .)) .) . (. head) . flip . ((flip . ((flip . (flip .)) .)) .) . flip . ((flip . ((flip . (ap .)) .)) .) . ap ((.) . ap . (liftM2 (ap . ((.) .) . flip (if' . (0 ==)) . (3 +)) .) . flip flip 2 . (flip .) . flip (.)) (ap (ap . (((.) . flip . ((ap . ((+) .) . liftM2 (+) toInteger) .)) .) . flip (flip . ((.) .))) . (. ap (+)) . flip . ((flip . ((.) .)) .) . flip (.)))) . (flip .) . flip flip (fix ((ap (flip if' ([]) . null) .) . (`ap` splitAt) . (((.) . liftM2 (:) fst) .) . flip flip snd . ((.) .))) . ((flip . ((flip . flip ((.) . ap (.) (map . (. map fromIntegral)))) .) . flip ((.) . flip zipWith [0..] . flip . ((!!) .))) .) . flip . flip id) .)) .) . ap ((.) . flip . (flip .) . (.) . (.) . map . (!!)) (map . (fromIntegral .) . flip rem . toInteger . length)) length) (fix ((1 :) . (2 :) . (3 :) . ap (zipWith (+) . tail . tail) (zipWith (+) =<< tail)))


main = do
    putStr "Nhập một chuỗi để trace (ví dụ: test): "
    hFlush stdout
    flag <- getLine
    let ascii_values = map ord flag
    
    -- Chúng ta sẽ dùng trace để in ra danh sách được tạo ra
    -- traceShowId sẽ in giá trị của tham số nó nhận và trả về chính giá trị đó
    let final_integer = generateNumberList (trace ("\nInput ASCII values: " ++ show ascii_values) ascii_values)

    putStrLn $ "\nFinal integer generated: " ++ show final_integer
    putStrLn "\nBây giờ hãy so sánh kết quả này với thuật toán bạn đã đảo ngược."
    putStrLn "Nếu nó khác, hãy tìm ra thuật toán đúng từ mối quan hệ input/output."