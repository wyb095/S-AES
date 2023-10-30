import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.List;
import java.util.ArrayList;
public class ExtendedSAES extends SAES {

    // 双重加密
    public static String doubleEncrypt(String plaintext, String key) {
        // 确保二进制密钥长度是32位
        if (key.length() != 32) {
            throw new IllegalArgumentException("Key must be a 32-bit binary string");
        }

        // 从32位二进制密钥中拆分为两个16位密钥
        String key1 = key.substring(0, 16);
        String key2 = key.substring(16);

        // 使用第一个密钥加密
        String intermediateCiphertext = encrypt(plaintext, key1);
        // 使用第二个密钥再次加密
        String finalCiphertext = encrypt(intermediateCiphertext, key2);

        return finalCiphertext;
    }
    

    // 双重解密
    public static String doubleDecrypt(String ciphertext, String key) {
        // 确保二进制密钥长度是32位
        if (key.length() != 32) {
            throw new IllegalArgumentException("Key must be a 32-bit binary string");
        }

        // 从32位二进制密钥中拆分为两个16位密钥
        String key1 = key.substring(0, 16);
        String key2 = key.substring(16,32);

        // 使用第二个密钥解密
        String intermediatePlaintext = decrypt(ciphertext, key2);
        // 使用第一个密钥再次解密
        String finalPlaintext = decrypt(intermediatePlaintext, key1);

        return finalPlaintext;
    }



    //三重加/解密
    public String tripleEncrypt(String plaintext, String key1, String key2, String key3) {

        String ciphertext1 = encrypt(plaintext, key1);

        String ciphertext2 = encrypt(ciphertext1, key2);
        String ciphertext3 = encrypt(ciphertext2, key3);
        // Return the final ciphertext
        return ciphertext3;
    }

    public String tripleDecrypt(String ciphertext, String key1, String key2, String key3) {

        String intermediatePlaintext2 = decrypt(ciphertext, key3);
        String intermediatePlaintext1 = decrypt(intermediatePlaintext2, key2);
        String plaintext = decrypt(intermediatePlaintext1, key1);
        // Return the final plaintext
        return plaintext;
    }
    // 矩阵转换为整数

    public static int matrixToInt(int[] array) {

        StringBuilder binString = new StringBuilder();
        for (int i : array) {
            binString.append(ToBinary(i, 4));
        }

        return Integer.parseInt(binString.toString(), 2);
    }

    // 中途相遇攻击
    public static List<String> meetInTheMiddleAttack(String[] plaintexts, String[] ciphertexts) {
        Map<Integer, Integer> intermediateValues = new HashMap<>();
        List<String> foundKeys = new ArrayList<>();

        // 枚举所有可能的16位密钥并加密每个明文
        for (int key1 = 0; key1 < 0x10000; key1++) {
            for (String plaintext : plaintexts) {
                String encrypted = encrypt(plaintext, Integer.toBinaryString(key1));
                int[] encryptedArray = From16to4(encrypted);
                int intermediateValue = matrixToInt(S_replace(encryptedArray));
                // 将中间值与第一个密钥映射存储在字典中
                intermediateValues.put(intermediateValue, key1);
            }
        }

        // 枚举所有可能的16位密钥并解密每个密文
        for (int key2 = 0; key2 < 0x10000; key2++) {
            for (String ciphertext : ciphertexts) {
                String decrypted = decrypt(ciphertext, Integer.toBinaryString(key2));
                int[] decryptedArray = From16to4(decrypted);
                int intermediateValue = matrixToInt(S_replace(decryptedArray));
                // 检查中间值是否在字典中
                if (intermediateValues.containsKey(intermediateValue)) {
                    // 如果找到匹配的中间值，表示成功找到了密钥
                    int foundKey1 = intermediateValues.get(intermediateValue);
                    // 合并密钥并以16进制表示
                    foundKeys.add(String.format("%04X%04X", foundKey1, key2));
                }
            }
        }
        return foundKeys.isEmpty() ? null : foundKeys;
    }
    public static List<Integer> parseCiphertext(String ciphertext) {
        List<Integer> ciphertextBlocks = new ArrayList<>();
        String[] binaryBlocks = ciphertext.split("\\s+"); // Split the string by spaces
        for (String binaryBlock : binaryBlocks) {
            // Parse each binary string to an integer and add it to the list
            ciphertextBlocks.add(Integer.parseInt(binaryBlock, 2));
        }
        return ciphertextBlocks;
    }

    // 生成随机的初始向量（IV）
    public static int generateRandomIV() {
        Random random = new Random();
        return random.nextInt(0xFFFF + 1);
    }

    // CBC模式加密
    public static List<String> cbcEncrypt(String plaintext, String keyStr, int iv) {
        List<String> ciphertextBlocks = new ArrayList<>();
        int[] plaintextBlocks = From16to4(plaintext);

        int previousBlock = iv;
        for (int plaintextBlock : plaintextBlocks) {
            // 将明文块与前一个密文块（或IV）进行异或运算
            int xoredBlock = plaintextBlock ^ previousBlock;
            // 加密异或后的块
            String encryptedBlock = encrypt(ToBinary(xoredBlock, 16), keyStr);
            // 将加密块的二进制字符串添加到密文列表
            ciphertextBlocks.add(encryptedBlock);
            // 更新前一个块为当前加密块的二进制整数形式
            previousBlock = Integer.parseInt(encryptedBlock, 2);
        }

        return ciphertextBlocks;
    }

    // CBC模式解密
    public static String cbcDecrypt(List<Integer> ciphertextBlocks, String keyStr, int iv) {
        StringBuilder plaintext = new StringBuilder();
        int previousBlock = iv;

        for (int ciphertextBlock : ciphertextBlocks) {
            // 解密当前密文块
            String decryptedBlock = decrypt(ToBinary(ciphertextBlock, 16), keyStr);
            // 将解密块转换为整数
            int decryptedBlockInt = Integer.parseInt(decryptedBlock, 2);
            // 将解密块与前一个密文块（或IV）进行异或运算
            int plaintextBlock = decryptedBlockInt ^ previousBlock;
            // 将得到的明文块添加到明文字符串
            plaintext.append(ToBinary(plaintextBlock, 16));
            // 更新前一个块为当前密文块
            previousBlock = ciphertextBlock;
        }

        return plaintext.toString();
    }
}