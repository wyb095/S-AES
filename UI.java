import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.List;

public class UI extends JFrame {
    private JTextField saesKeyField;
    private JTextArea saesInputText;
    private JTextArea saesOutputText;
    private JTextField doubleKeyField;
    private JTextArea doubleInputText;
    private JTextArea doubleOutputText;
    private JTextField tripleKey1Field;
    private JTextField tripleKey2Field;
    private JTextField tripleKey3Field;
    private JTextArea tripleInputText;
    private JTextArea tripleOutputText;
    private JTextArea meetInMiddleInputText;
    private JTextArea meetInMiddleOutputText;
    private JTextField cbcKeyField;
    private JTextArea cbcInputText;
    private JTextArea cbcOutputText;
    private JLabel cbcIVLabel;
    private JTextField cbcIVField;
    public UI() {
        setTitle("Extended SAES UI");
        setSize(600, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        JTabbedPane tabbedPane = new JTabbedPane();
        JPanel saesPanel = createSAESPanel();
        tabbedPane.addTab("SAES", saesPanel);

        JPanel doublePanel = createDoublePanel();
        JPanel triplePanel = createTriplePanel();
        JPanel meetInMiddlePanel = createMeetInMiddlePanel();
        JPanel cbcPanel = createCBCPanel();

        tabbedPane.addTab("Double Encrypt/Decrypt", doublePanel);
        tabbedPane.addTab("Triple Encrypt/Decrypt", triplePanel);
        tabbedPane.addTab("Meet In The Middle Attack", meetInMiddlePanel);
        tabbedPane.addTab("CBC Mode", cbcPanel);

        add(tabbedPane, BorderLayout.CENTER);
    }
    private JPanel createSAESPanel() {
        JPanel panel = new JPanel(new GridLayout(0, 1));

        saesKeyField = new JTextField();
        saesInputText = new JTextArea(5, 20);
        saesOutputText = new JTextArea(5, 20);
        saesOutputText.setEditable(false);

        panel.add(new JLabel("16-bit Binary Key:"));
        panel.add(saesKeyField);

        panel.add(new JLabel("Input Text (Plaintext or Ciphertext):"));
        panel.add(new JScrollPane(saesInputText));

        JButton encryptButton = new JButton("Encrypt");
        encryptButton.addActionListener(this::handleSAESEncrypt);
        panel.add(encryptButton);

        JButton decryptButton = new JButton("Decrypt");
        decryptButton.addActionListener(this::handleSAESDecrypt);
        panel.add(decryptButton);

        panel.add(new JLabel("Output Text:"));
        panel.add(new JScrollPane(saesOutputText));

        return panel;
    }
    private void handleSAESEncrypt(ActionEvent event) {
        try {
            String key = saesKeyField.getText();
            String plaintext = saesInputText.getText();
            String encryptedText = SAES.encrypt(plaintext, key);
            saesOutputText.setText(encryptedText);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error during SAES Encryption: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void handleSAESDecrypt(ActionEvent event) {
        try {
            String key = saesKeyField.getText();
            String ciphertext = saesInputText.getText();
            String decryptedText = SAES.decrypt(ciphertext, key);
            saesOutputText.setText(decryptedText);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error during SAES Decryption: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
    private JPanel createDoublePanel() {
        JPanel panel = new JPanel(new GridLayout(0, 1));

        doubleKeyField = new JTextField();
        doubleInputText = new JTextArea(5, 20);
        doubleOutputText = new JTextArea(5, 20);
        doubleOutputText.setEditable(false);

        panel.add(new JLabel("32-bit Binary Key:"));
        panel.add(doubleKeyField);

        panel.add(new JLabel("Input Text (Plaintext or Ciphertext):"));
        panel.add(new JScrollPane(doubleInputText));

        JButton doubleEncryptButton = new JButton("Encrypt");
        doubleEncryptButton.addActionListener(this::handleDoubleEncrypt);
        panel.add(doubleEncryptButton);

        JButton doubleDecryptButton = new JButton("Decrypt");
        doubleDecryptButton.addActionListener(this::handleDoubleDecrypt);
        panel.add(doubleDecryptButton);

        panel.add(new JLabel("Output Text:"));
        panel.add(new JScrollPane(doubleOutputText));

        return panel;
    }

    private void handleDoubleEncrypt(ActionEvent event) {
        try {
            String binaryKey = doubleKeyField.getText(); // Get binary key as a string

            if (binaryKey.length() != 32 || !binaryKey.matches("[01]+")) {
                JOptionPane.showMessageDialog(this, "Key must be a 32-bit binary number.", "Key Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            String plaintext = doubleInputText.getText();
            String encryptedText = ExtendedSAES.doubleEncrypt(plaintext, binaryKey);
            doubleOutputText.setText(encryptedText);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error during encryption: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void handleDoubleDecrypt(ActionEvent event) {
        try {
            String binaryKey = doubleKeyField.getText();
            // Ensure the binary key is a 32-bit binary string
            if (binaryKey.length() != 32 || !binaryKey.matches("[01]+")) {
                JOptionPane.showMessageDialog(this, "Key must be a 32-bit binary number.", "Key Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            String ciphertext = doubleInputText.getText();
            String decryptedText = ExtendedSAES.doubleDecrypt(ciphertext, binaryKey);
            doubleOutputText.setText(decryptedText);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error during decryption: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }


    private JPanel createTriplePanel() {
        JPanel panel = new JPanel(new GridLayout(0, 1));

        tripleKey1Field = new JTextField();
        tripleKey2Field = new JTextField();
        tripleKey3Field = new JTextField();
        tripleInputText = new JTextArea(5, 20);
        tripleOutputText = new JTextArea(5, 20);
        tripleOutputText.setEditable(false);

        panel.add(new JLabel("First 16-bit Binary Key:"));
        panel.add(tripleKey1Field);
        panel.add(new JLabel("Second 16-bit Binary Key:"));
        panel.add(tripleKey2Field);
        panel.add(new JLabel("Third 16-bit Binary Key:"));
        panel.add(tripleKey3Field);

        panel.add(new JLabel("Input Text (Plaintext or Ciphertext):"));
        panel.add(new JScrollPane(tripleInputText));

        JButton tripleEncryptButton = new JButton("Encrypt");
        tripleEncryptButton.addActionListener(this::handleTripleEncrypt);
        panel.add(tripleEncryptButton);

        JButton tripleDecryptButton = new JButton("Decrypt");
        tripleDecryptButton.addActionListener(this::handleTripleDecrypt);
        panel.add(tripleDecryptButton);

        panel.add(new JLabel("Output Text:"));
        panel.add(new JScrollPane(tripleOutputText));

        return panel;
    }

    private void handleTripleEncrypt(ActionEvent event) {
        try {
            String key1 = tripleKey1Field.getText();
            String key2 = tripleKey2Field.getText();
            String key3 = tripleKey3Field.getText();
            String plaintext = tripleInputText.getText();
            String encryptedText = new ExtendedSAES().tripleEncrypt(plaintext, key1, key2, key3);
            tripleOutputText.setText(encryptedText);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error during encryption: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void handleTripleDecrypt(ActionEvent event) {
        try {
            String key1 = tripleKey1Field.getText();
            String key2 = tripleKey2Field.getText();
            String key3 = tripleKey3Field.getText();
            String ciphertext = tripleInputText.getText();
            String decryptedText = new ExtendedSAES().tripleDecrypt(ciphertext, key1, key2, key3);
            tripleOutputText.setText(decryptedText);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error during decryption: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private JPanel createMeetInMiddlePanel() {
        JPanel panel = new JPanel(new GridLayout(0, 1));

        meetInMiddleInputText = new JTextArea(10, 20);
        meetInMiddleOutputText = new JTextArea(10, 20);
        meetInMiddleOutputText.setEditable(false);

        panel.add(new JLabel("Enter Plaintext-Ciphertext pairs (separated by spaces):"));
        panel.add(new JScrollPane(meetInMiddleInputText));

        JButton meetInMiddleButton = new JButton("Attack");
        meetInMiddleButton.addActionListener(this::handleMeetInMiddle);
        panel.add(meetInMiddleButton);

        panel.add(new JLabel("Possible Keys:"));
        panel.add(new JScrollPane(meetInMiddleOutputText));

        return panel;
    }

    private void handleMeetInMiddle(ActionEvent event) {
        try {
            String[] lines = meetInMiddleInputText.getText().split("\\n");
            String[] plaintexts = new String[lines.length];
            String[] ciphertexts = new String[lines.length];
            for (int i = 0; i < lines.length; i++) {
                String[] parts = lines[i].split("\\s+");
                plaintexts[i] = parts[0];
                ciphertexts[i] = parts[1];
            }
            List<String> keys = ExtendedSAES.meetInTheMiddleAttack(plaintexts, ciphertexts);
            meetInMiddleOutputText.setText(keys != null && !keys.isEmpty() ? String.join("\n", keys) : "No keys found.");
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error during Meet In The Middle Attack: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private JPanel createCBCPanel() {
        JPanel panel = new JPanel(new GridLayout(0, 1));

        cbcKeyField = new JTextField();
        cbcIVField = new JTextField();
        cbcInputText = new JTextArea(5, 20);
        cbcOutputText = new JTextArea(5, 20);
        cbcOutputText.setEditable(false);
        cbcIVLabel = new JLabel("IV: Not generated yet");

        panel.add(new JLabel("16-bit Binary Key:"));
        panel.add(cbcKeyField);
        panel.add(new JLabel("IV (for decryption):")); // label for the new IV input field
        panel.add(cbcIVField);
        panel.add(new JLabel("Input Text (Plaintext or Ciphertext):"));
        panel.add(new JScrollPane(cbcInputText));

        JButton cbcEncryptButton = new JButton("Encrypt");
        cbcEncryptButton.addActionListener(this::handleCBCEncrypt);
        panel.add(cbcEncryptButton);

        JButton cbcDecryptButton = new JButton("Decrypt");
        cbcDecryptButton.addActionListener(this::handleCBCDecrypt);
        panel.add(cbcDecryptButton);

        panel.add(cbcIVLabel);
        panel.add(new JLabel("Output Text:"));
        panel.add(new JScrollPane(cbcOutputText));

        return panel;
    }

    private void handleCBCEncrypt(ActionEvent event) {
        try {
            String key = cbcKeyField.getText();
            String plaintext = cbcInputText.getText();
            int iv = ExtendedSAES.generateRandomIV();
            cbcIVLabel.setText("IV: " + Integer.toBinaryString(iv));

            List<String> encryptedBlocks = ExtendedSAES.cbcEncrypt(plaintext, key, iv);

            String encryptedText = String.join(" ", encryptedBlocks);
            cbcOutputText.setText(encryptedText); // Display the encrypted binary blocks
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error during CBC Encryption: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void handleCBCDecrypt(ActionEvent event) {
        try {
            String key = cbcKeyField.getText();
            String ciphertext = cbcInputText.getText();
            // Parse the IV from the cbcIVField instead of cbcIVLabel
            int iv = Integer.parseInt(cbcIVField.getText(), 2);
            List<Integer> ciphertextBlocks = ExtendedSAES.parseCiphertext(ciphertext); // Assume this method is implemented to convert the string to a List<Integer>
            String decryptedText = ExtendedSAES.cbcDecrypt(ciphertextBlocks, key, iv);
            cbcOutputText.setText(decryptedText);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error during CBC Decryption: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            UI ui = new UI();
            ui.setVisible(true);
        });
    }
}
