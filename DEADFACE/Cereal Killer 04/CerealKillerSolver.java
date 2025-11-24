import java.security.MessageDigest;

public class CerealKillerSolver {

    private static final String TARGET_HASH = "cc2b7d09f0a7732319328eb5dd4a1167ac34957489f384d68586a7d23909ed7654d2c3b7f50f33289aeaecf8685f0a2eb60ba269aeb448e9173fa14";

    // Danh sách các mật khẩu khả thi, dựa trên chủ đề "Monster Cereals"
    private static final String[] CEREAL_GUESSES = {
        "Count Chocula",
        "Franken Berry",
        "Boo Berry",
        "Fruit Brute",
        "Yummy Mummy",
        "Lucky Charms", // Thêm một vài loại phổ biến khác để chắc chắn
        "Trix",
        "Cap'n Crunch"
    };

    public static String hashPassword(String password) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
            byte[] arrayOfByte = messageDigest.digest(password.getBytes("UTF-8"));
            StringBuilder stringBuilder = new StringBuilder();
            for (byte b : arrayOfByte) {
                String str = Integer.toHexString(0xFF & b);
                if (str.length() == 1)
                    stringBuilder.append('0');
                stringBuilder.append(str);
            }
            return stringBuilder.toString();
        } catch (Exception exception) {
            throw new RuntimeException(exception);
        }
    }

    public static void main(String[] args) {
        System.out.println("[*] Bắt đầu quá trình tìm kiếm mật khẩu trong từ điển Cereal...");

        for (String currentGuess : CEREAL_GUESSES) {
            
            System.out.println("    -> Đang thử: \"" + currentGuess + "\"");
            String calculatedHash = hashPassword(currentGuess);

            if (TARGET_HASH.equals(calculatedHash)) {
                System.out.println("\n[+] TÌM THẤY!");
                System.out.println("    - Mật khẩu chính xác là: \"" + currentGuess + "\"");
                System.out.println("\n[*] Flag cuối cùng là:");
                System.out.println("    deadface{\"" + currentGuess + "\"}");
                return;
            }
        }

        System.out.println("\n[-] Không tìm thấy mật khẩu trong danh sách từ điển.");
    }
}